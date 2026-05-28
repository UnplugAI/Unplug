"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.safeguards.base import RegexScanner
from unplug.safeguards.injection.patterns import INJECTION_PATTERNS

_DEFAULT_CONFIG = ScannerConfig(base_score=0.85, normalize=True)


class InjectionScanner(RegexScanner):
    name = "injection"
    _patterns = INJECTION_PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

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
                    evidence=f"Matched pattern: {subcategory}",
                    replacement=self._get_replacement(subcategory),
                )

        if norm_result.reversed_text:
            for subcategory, pattern in self._patterns:
                for match in pattern.finditer(norm_result.reversed_text):
                    score = self._compute_score(subcategory, text)
                    yield Finding(
                        category=self.name,
                        subcategory=f"{subcategory}_reversed",
                        stage="regex",
                        span_start=0,
                        span_end=len(text.text),
                        score=score,
                        evidence=f"Reversed text matched: {subcategory}",
                        replacement=None,
                    )
