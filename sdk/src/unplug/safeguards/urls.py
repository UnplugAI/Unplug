"""Malicious URL scanner — offline heuristics for hostile links.

Covers the LLM Guard MaliciousURLs gap without a model or network calls:
data: URI payloads, credentials-in-URL, IP-literal hosts, punycode and
homoglyph hostnames, and link shorteners that hide the real destination.
"""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding
from unplug.safeguards.base import RegexScanner

_SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "tiny.cc",
    "rebrand.ly",
    "shorturl.at",
    "lnkd.in",
    "s.id",
)

_SHORTENER_RE = "|".join(re.escape(d) for d in _SHORTENER_DOMAINS)

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "data_uri_payload",
        re.compile(r"(?i)\bdata:(?:text/(?:html|javascript)|application/[\w+.-]+)[;,]"),
    ),
    (
        "credentials_in_url",
        re.compile(r"(?i)\bhttps?://[^/\s:@]+:[^/\s:@]+@[\w.-]+"),
    ),
    (
        "ip_literal_url",
        re.compile(
            r"(?i)\bhttps?://(?:\d{1,3}(?:\.\d{1,3}){3}|0x[0-9a-f]{6,8}|\d{8,10})(?::\d+)?(?=[/\s\"'<>)\]?#]|$)",
        ),
    ),
    (
        "punycode_host",
        re.compile(r"(?i)\bhttps?://(?:[\w-]+\.)*xn--[\w-]+(?:\.[\w-]+)*"),
    ),
    (
        "homoglyph_host",
        re.compile(r"(?i)\bhttps?://(?:[\w.-]*[^\x00-\x7f][\w.-]*)(?=[/:?\s\"'<>)\]]|$)"),
    ),
    (
        "url_shortener",
        re.compile(rf"(?i)\bhttps?://(?:www\.)?(?:{_SHORTENER_RE})/[\w\-/]+"),
    ),
]

_SCORES: dict[str, float] = {
    "data_uri_payload": 0.85,
    "credentials_in_url": 0.85,
    "ip_literal_url": 0.7,
    "punycode_host": 0.75,
    "homoglyph_host": 0.8,
    "url_shortener": 0.6,
}

_DEFAULT_CONFIG = ScannerConfig(base_score=0.7)


class MaliciousUrlScanner(RegexScanner):
    """Flags URLs that hide payloads, destinations, or credentials."""

    name = "urls"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)

    def _should_scan(self, text: TaintedText) -> bool:
        # URLs typed by the user are routine; hostile links arrive through
        # retrieved documents, tool output, and model output.
        return text.trust_level in (
            TrustLevel.TOOL_OUTPUT,
            TrustLevel.RETRIEVED,
            TrustLevel.EXTERNAL,
            TrustLevel.UNKNOWN,
        )

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        seen: set[tuple[int, int]] = set()
        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(text.text):
                span = (match.start(), match.end())
                if span in seen:
                    continue
                seen.add(span)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span[0],
                    span_end=span[1],
                    score=self._compute_score(subcategory, text),
                    evidence=self._make_evidence(subcategory),
                    replacement="[BLOCKED:url]",
                )

    def _compute_score(self, subcategory: str, text: TaintedText) -> float:
        return _SCORES.get(subcategory, self._config.base_score)

    def _make_evidence(self, subcategory: str) -> str:
        return f"Suspicious URL: {subcategory.replace('_', ' ')}"
