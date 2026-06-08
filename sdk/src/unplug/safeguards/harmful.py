"""Harmful output scanner — detects toxic, dangerous, and policy-violating content."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding
from unplug.safeguards.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "dangerous_instructions",
        re.compile(
            r"(?i)\b(how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive|poison))\b",
        ),
    ),
    (
        "self_harm",
        re.compile(
            r"(?i)\b(suicide|self[- ]harm|kill\s+(your|my)self|end\s+(your|my)\s+life)\b",
        ),
    ),
    (
        "illegal_activity",
        re.compile(
            r"(?i)\b(hack\s+into|steal\s+(credentials?|passwords?)|phishing|ransomware)\b",
        ),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.75)


class HarmfulScanner(RegexScanner):
    name = "harmful"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

    def _should_scan(self, text: TaintedText) -> bool:
        return text.trust_level in (
            TrustLevel.TOOL_OUTPUT,
            TrustLevel.RETRIEVED,
            TrustLevel.EXTERNAL,
        )

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        normalized = norm_result.text
        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                score = self._compute_score(subcategory, text)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=score,
                    evidence=self._make_evidence(subcategory),
                    replacement=self._get_replacement(subcategory),
                )

    def _make_evidence(self, subcategory: str) -> str:
        return f"Potentially harmful content: {subcategory}"
