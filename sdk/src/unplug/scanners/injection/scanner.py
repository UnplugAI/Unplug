"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer, cached_normalize
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.scanners.base import RegexScanner
from unplug.scanners.injection.patterns import INJECTION_PATTERNS

_DEFAULT_CONFIG = default_scanner_config("injection")


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
        norm_result = cached_normalize(context, self._normalizer, text.text, cache_key="full")
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

        evasion_stages = {"zero_width", "homoglyphs", "fullwidth", "enclosed"}
        if evasion_stages.intersection(norm_result.stages_applied):
            score = self._compute_score("invisible_text", text)
            yield Finding(
                category=self.name,
                subcategory="invisible_text",
                stage="normalize",
                span_start=0,
                span_end=len(text.text),
                score=score,
                evidence=(
                    "Invisible or homoglyph evasion stripped during normalization: "
                    f"{', '.join(sorted(evasion_stages.intersection(norm_result.stages_applied)))}"
                ),
                replacement=self._get_replacement("invisible_text"),
            )

        if norm_result.reversed_text:
            for subcategory, pattern in self._patterns:
                for _match in pattern.finditer(norm_result.reversed_text):
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
