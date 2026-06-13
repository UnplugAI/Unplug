"""Destructive action scanner: prevents agents from dangerous operations."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer, cached_normalize
from unplug.core.pattern_loader import load_compiled_patterns
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.scanners.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = list(load_compiled_patterns("destructive.yaml"))

_DEFAULT_CONFIG = default_scanner_config("destructive")


class DestructiveScanner(RegexScanner):
    name = "destructive"
    _patterns = _PATTERNS

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
                    evidence=self._make_evidence(subcategory),
                    replacement=self._get_replacement(subcategory),
                )

    def _make_evidence(self, subcategory: str) -> str:
        return f"Destructive operation detected: {subcategory}"
