"""Malicious URL scanner: offline heuristics for hostile links.

Covers the LLM Guard MaliciousURLs gap without a model or network calls:
data: URI payloads, credentials-in-URL, IP-literal hosts, punycode and
homoglyph hostnames, and link shorteners that hide the real destination.
"""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.pattern_loader import load_compiled_patterns
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.scanners.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern[str]]] = list(load_compiled_patterns("urls.yaml"))

_SCORES: dict[str, float] = {
    "data_uri_payload": 0.85,
    "credentials_in_url": 0.85,
    "ip_literal_url": 0.7,
    "punycode_host": 0.75,
    "homoglyph_host": 0.8,
    "url_shortener": 0.6,
}

_DEFAULT_CONFIG = default_scanner_config("urls")


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
