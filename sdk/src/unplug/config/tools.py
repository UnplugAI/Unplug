"""Tool classification policy: side-effect vs read-only (CaMeL-style boundary)."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

from unplug.data.maps_loader import load_tool_patterns_map


class ToolProfile(StrEnum):
    READONLY = "readonly"
    MESSAGING = "messaging"
    FULL = "full"


def _build_profile_pattern_maps() -> tuple[
    dict[ToolProfile, tuple[str, ...]],
    dict[ToolProfile, tuple[str, ...] | None],
]:
    data = load_tool_patterns_map()
    blocked: dict[ToolProfile, tuple[str, ...]] = {}
    allowed: dict[ToolProfile, tuple[str, ...] | None] = {}
    for key, entry in data.profiles.items():
        try:
            profile = ToolProfile(key)
        except ValueError:
            continue
        blocked[profile] = entry.blocked_patterns
        allowed[profile] = entry.allowed_patterns
    return blocked, allowed


_tool_maps = load_tool_patterns_map()
DEFAULT_SIDE_EFFECT_PATTERNS = _tool_maps.side_effect
DEFAULT_TAINT_SOURCE_PATTERNS = _tool_maps.taint_source
DEFAULT_READ_ONLY_PATTERNS = _tool_maps.read_only
PROFILE_BLOCKED_PATTERNS, PROFILE_ALLOWED_PATTERNS = _build_profile_pattern_maps()


def _compile(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def _matches_token(rx: re.Pattern[str], variant: str) -> bool:
    """True when rx matches whole underscore tokens of variant, not part of one.

    The patterns are verb prefixes (^pay, ^post, ^rm, ^exec). Matching them against
    a bare suffix means a prefix of a longer word counts: ^pay hits payload, ^post
    hits postgres and postcode, ^rm hits rma. Those are read tools, and classifying
    them as side effects denies them under the readonly profile. Requiring the match
    to end where a token ends keeps ^delete on delete_file and drops ^pay on payload.
    """
    return any(m.end() == len(variant) or variant[m.end()] == "_" for m in rx.finditer(variant))


def _any_match(regexes: list[re.Pattern[str]], variants: tuple[str, ...]) -> bool:
    return any(_matches_token(rx, v) for rx in regexes for v in variants)


# Splits camelCase and PascalCase at the boundary, so WebFetch becomes web_fetch
# and sendEmail becomes send_email. The second alternative handles runs of capitals
# followed by a word, as in HTTPPost -> http_post.
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# Namespace separators, longest first. MCP uses mcp__server__tool; agent hosts use
# server:tool or server.tool.
_NAMESPACE_SEPARATORS = ("__", ":", ".", "/")
_SEPARATOR_SPLIT = re.compile("|".join(re.escape(s) for s in _NAMESPACE_SEPARATORS))


def _normalize_tool_name(tool_name: str) -> str:
    """Flatten a namespaced or camelCase tool name to underscore-delimited tokens.

    Every segment is kept, not just the last one. Keeping only the last segment
    dropped the verb whenever a host put it first (delete.file, exec.command,
    server/delete/user all became a harmless-looking noun) and produced the empty
    string for a trailing separator, which classified as nothing at all. The host
    prefix is still not what decides whether a call has side effects, but it does
    not need to be discarded here: _name_variants walks the suffixes, so the verb
    is found wherever in the name it sits.
    """
    name = tool_name.strip()
    segments = [s for s in _SEPARATOR_SPLIT.split(name) if s]
    name = "_".join(segments)
    name = _CAMEL_BOUNDARY.sub("_", name)
    return name.replace("-", "_").strip("_").lower()


def _name_variants(tool_name: str) -> tuple[str, ...]:
    """The normalized name plus each of its underscore-delimited suffixes.

    Classification patterns are anchored at the start, which misses the very common
    vendor-prefixed shape: slack_post_message and github_create_issue are a post and
    a create, but neither starts with one. Matching every suffix as well means the
    verb is found wherever the vendor chose to put it (#166).
    """
    norm = _normalize_tool_name(tool_name)
    if not norm:
        return ()
    parts = norm.split("_")
    return tuple("_".join(parts[i:]) for i in range(len(parts)))


def resolve_profile(name: str | None) -> ToolProfile | None:
    if not name:
        return None
    lowered = name.strip().lower()
    for profile in ToolProfile:
        if profile.value == lowered:
            return profile
    msg = f"Unknown tool profile: {name!r} (use readonly, messaging, full)"
    raise ValueError(msg)


def is_tool_permitted_by_profile(tool_name: str, profile: ToolProfile | None) -> bool:
    if profile is None or profile is ToolProfile.FULL:
        return True
    variants = _name_variants(tool_name)
    blocked = _compile(PROFILE_BLOCKED_PATTERNS.get(profile, ()))
    if _any_match(blocked, variants):
        return False
    allowed_patterns = PROFILE_ALLOWED_PATTERNS.get(profile)
    if allowed_patterns is None:
        return True
    allowed = _compile(allowed_patterns)
    return _any_match(allowed, variants)


class ToolPolicyConfig(BaseModel):
    """Classify tools for session taint + side-effect review gates."""

    model_config = {"frozen": True}

    enabled: bool = True
    session_taint_enabled: bool = True
    tainted_side_effect_review_score: float = Field(default=0.35, ge=0.0, le=1.0)

    side_effect_patterns: tuple[str, ...] = DEFAULT_SIDE_EFFECT_PATTERNS
    side_effect_tools: tuple[str, ...] = Field(default_factory=tuple)

    taint_source_patterns: tuple[str, ...] = DEFAULT_TAINT_SOURCE_PATTERNS
    taint_source_tools: tuple[str, ...] = Field(default_factory=tuple)

    read_only_patterns: tuple[str, ...] = DEFAULT_READ_ONLY_PATTERNS
    read_only_tools: tuple[str, ...] = Field(default_factory=tuple)

    unknown_tool_is_side_effect: bool = Field(
        default=True,
        description=(
            "Hold a tool whose name matches nothing known for review while the session "
            "is tainted. Set false to restore the pre-#166 behaviour of allowing it."
        ),
    )

    profile: str | None = Field(
        default=None,
        description="Tool access tier: readonly, messaging, or full",
    )

    def resolved_profile(self) -> ToolProfile | None:
        return resolve_profile(self.profile)

    def is_permitted(self, tool_name: str) -> bool:
        return is_tool_permitted_by_profile(tool_name, self.resolved_profile())

    def _side_effect_regexes(self) -> list[re.Pattern[str]]:
        return _compile(self.side_effect_patterns)

    def _taint_source_regexes(self) -> list[re.Pattern[str]]:
        return _compile(self.taint_source_patterns)

    def is_side_effect(self, tool_name: str) -> bool:
        variants = _name_variants(tool_name)
        configured = {_normalize_tool_name(t) for t in self.side_effect_tools}
        if configured.intersection(variants):
            return True
        return _any_match(self._side_effect_regexes(), variants)

    def is_taint_source(self, tool_name: str) -> bool:
        variants = _name_variants(tool_name)
        configured = {_normalize_tool_name(t) for t in self.taint_source_tools}
        if configured.intersection(variants):
            return True
        return _any_match(self._taint_source_regexes(), variants)

    def _read_only_regexes(self) -> list[re.Pattern[str]]:
        return _compile(self.read_only_patterns)

    def is_read_only(self, tool_name: str) -> bool:
        return not self.is_side_effect(tool_name)

    def is_known_read_only(self, tool_name: str) -> bool:
        """Positively recognised as having no side effect, rather than merely unmatched."""
        variants = _name_variants(tool_name)
        configured = {_normalize_tool_name(t) for t in self.read_only_tools}
        if configured.intersection(variants):
            return True
        if _any_match(self._taint_source_regexes(), variants):
            return True
        return _any_match(self._read_only_regexes(), variants)

    def is_unclassified(self, tool_name: str) -> bool:
        """Matches none of the side-effect, taint-source, or read-only tables."""
        return not self.is_side_effect(tool_name) and not self.is_known_read_only(tool_name)
