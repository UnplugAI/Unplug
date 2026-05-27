"""Tool classification policy — side-effect vs read-only (CaMeL-style boundary)."""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field

# Side-effect tools: mutate state, send messages, run commands, pay money.
DEFAULT_SIDE_EFFECT_PATTERNS: tuple[str, ...] = (
    r"^exec",
    r"^shell",
    r"^bash",
    r"^run_terminal",
    r"^run_command",
    r"^terminal",
    r"^write",
    r"^edit",
    r"^apply_patch",
    r"^write_file",
    r"^create_file",
    r"^delete",
    r"^remove",
    r"^send_message",
    r"^send_email",
    r"^post_message",
    r"^message_send",
    r"^browser_click",
    r"^browser_type",
    r"^browser_navigate",
    r"^pay",
    r"^transfer",
    r"^stripe",
    r"^rm",
    r"drop_table",
    r"run_query",
    r"db_exec",
)

# Taint-source tools: pull untrusted external content into the session.
DEFAULT_TAINT_SOURCE_PATTERNS: tuple[str, ...] = (
    r"^web_fetch",
    r"^web_search",
    r"^fetch",
    r"^browser",
    r"^read",
    r"^read_file",
    r"^grep",
    r"^search",
    r"^scrape",
    r"^http",
)


class ToolProfile(StrEnum):
    READONLY = "readonly"
    MESSAGING = "messaging"
    FULL = "full"


PROFILE_BLOCKED_PATTERNS: dict[ToolProfile, tuple[str, ...]] = {
    ToolProfile.READONLY: DEFAULT_SIDE_EFFECT_PATTERNS,
    ToolProfile.MESSAGING: (
        r"^exec",
        r"^shell",
        r"^bash",
        r"^run_terminal",
        r"^run_command",
        r"^terminal",
        r"^write",
        r"^edit",
        r"^apply_patch",
        r"^write_file",
        r"^create_file",
        r"^delete",
        r"^remove",
        r"^browser_click",
        r"^browser_type",
        r"^browser_navigate",
        r"^pay",
        r"^transfer",
        r"^stripe",
        r"^rm",
        r"drop_table",
        r"run_query",
        r"db_exec",
    ),
    ToolProfile.FULL: (),
}

PROFILE_ALLOWED_PATTERNS: dict[ToolProfile, tuple[str, ...] | None] = {
    ToolProfile.READONLY: (
        r"^search",
        r"^grep",
        r"^read",
        r"^lookup",
        r"^scan",
        r"^list",
        r"^get",
        r"^fetch",
        r"^web_search",
        r"^session",
    ),
    ToolProfile.MESSAGING: None,
    ToolProfile.FULL: None,
}


def _compile(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


def _normalize_tool_name(tool_name: str) -> str:
    name = tool_name.strip().lower()
    if ":" in name:
        name = name.split(":")[-1]
    if "." in name:
        name = name.split(".")[-1]
    return name


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
    norm = _normalize_tool_name(tool_name)
    blocked = _compile(PROFILE_BLOCKED_PATTERNS.get(profile, ()))
    if any(rx.search(norm) for rx in blocked):
        return False
    allowed_patterns = PROFILE_ALLOWED_PATTERNS.get(profile)
    if allowed_patterns is None:
        return True
    allowed = _compile(allowed_patterns)
    return any(rx.search(norm) for rx in allowed)


class ToolPolicyConfig(BaseModel):
    """Classify tools for session taint + side-effect review gates."""

    model_config = {"frozen": True}

    enabled: bool = True
    session_taint_enabled: bool = True
    tainted_side_effect_review_score: float = Field(default=0.75, ge=0.0, le=1.0)

    side_effect_patterns: tuple[str, ...] = DEFAULT_SIDE_EFFECT_PATTERNS
    side_effect_tools: tuple[str, ...] = Field(default_factory=tuple)

    taint_source_patterns: tuple[str, ...] = DEFAULT_TAINT_SOURCE_PATTERNS
    taint_source_tools: tuple[str, ...] = Field(default_factory=tuple)

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
        norm = _normalize_tool_name(tool_name)
        if norm in {t.lower() for t in self.side_effect_tools}:
            return True
        return any(rx.search(norm) for rx in self._side_effect_regexes())

    def is_taint_source(self, tool_name: str) -> bool:
        norm = _normalize_tool_name(tool_name)
        if norm in {t.lower() for t in self.taint_source_tools}:
            return True
        return any(rx.search(norm) for rx in self._taint_source_regexes())

    def is_read_only(self, tool_name: str) -> bool:
        return not self.is_side_effect(tool_name)
