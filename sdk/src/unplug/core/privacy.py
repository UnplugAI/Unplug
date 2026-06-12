"""Privacy Filter protocol — implementation ships with unplug-safeguard model only."""

from __future__ import annotations

import logging
import re
from typing import Protocol

from unplug.api.types import Finding

_logger = logging.getLogger("unplug.privacy")

_LEAKAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key_generic",
        re.compile(
            r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}",
        ),
    ),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("email_address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_number", re.compile(r"\b(\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b")),
]

_PF_LABEL_MAP: dict[str, str] = {
    "api_key_generic": "secret",
    "aws_key": "secret",
    "email_address": "private_email",
    "phone_number": "private_phone",
}


class PrivacyFilterService(Protocol):
    """Server-side stage after unplug-safeguard model is released."""

    @property
    def is_loaded(self) -> bool: ...

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]: ...


class NullPrivacyFilter:
    """Default for SDK and server until unplug-safeguard is deployed."""

    @property
    def is_loaded(self) -> bool:
        return False

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]:
        return baseline


class HeuristicPrivacyFilter:
    """Regex stand-in until unplug-safeguard PF model ships."""

    @property
    def is_loaded(self) -> bool:
        return True

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]:
        covered = {(f.span_start, f.span_end) for f in baseline}
        extra: list[Finding] = []
        for subcategory, pattern in _LEAKAGE_PATTERNS:
            pf_label = _PF_LABEL_MAP.get(subcategory, "private_other")
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                if span in covered:
                    continue
                extra.append(
                    Finding(
                        category="leakage",
                        subcategory=pf_label,
                        stage="privacy_filter",
                        span_start=match.start(),
                        span_end=match.end(),
                        score=0.82,
                        evidence=f"Privacy filter matched {pf_label}",
                        replacement=None,
                    )
                )
                covered.add(span)
        return [*baseline, *extra]


def build_privacy_filter(*, enabled: bool, dev_heuristic: bool = False) -> PrivacyFilterService:
    """Build privacy filter stage. SDK uses heuristic only when explicitly requested."""
    if not enabled:
        return NullPrivacyFilter()
    if dev_heuristic:
        return HeuristicPrivacyFilter()
    _logger.warning(
        "privacy_filter_enabled without dev_heuristic; using NullPrivacyFilter until "
        "unplug-safeguard model ships"
    )
    return NullPrivacyFilter()
