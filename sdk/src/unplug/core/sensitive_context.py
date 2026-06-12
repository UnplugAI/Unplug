"""Sensitive-context dual mode — tighten policy when secrets/tokens are in play."""

from __future__ import annotations

import re

from unplug.api.types import Finding

_SENSITIVE_MARKERS = re.compile(
    r"(?i)\b("
    r"session\s+token|api\s*[_-]?key|secret\s*[_-]?key|access\s+token|bearer\s+token|"
    r"auth\s+token|refresh\s+token|password|credentials?|private\s+key|"
    r"signing\s+key|oauth\s+token|(?:session|auth)\s+cookie|session\s+token.*browser\s+tab"
    r")\b"
)

_BOOST_CATEGORIES = frozenset({"injection", "leakage"})


def has_sensitive_context(text: str) -> bool:
    """True when the text discusses credentials, tokens, or secret material."""
    return bool(_SENSITIVE_MARKERS.search(text))


def apply_sensitive_context_boost(
    findings: list[Finding],
    text: str,
    *,
    enabled: bool,
    score_boost: float,
    block_threshold_delta: float,
) -> tuple[list[Finding], float]:
    """Boost injection/leakage scores and lower effective block threshold in sensitive context."""
    if not enabled or not has_sensitive_context(text):
        return findings, 0.0

    boosted: list[Finding] = []
    for finding in findings:
        if finding.category in _BOOST_CATEGORIES:
            boosted.append(
                finding.model_copy(
                    update={"score": min(1.0, finding.score + score_boost)},
                )
            )
        else:
            boosted.append(finding)

    return boosted, block_threshold_delta
