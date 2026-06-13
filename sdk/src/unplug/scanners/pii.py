"""Presidio-backed PII scanner: optional NER + recognizer layer on output/retrieved text."""

from __future__ import annotations

import logging
from collections.abc import Generator
from typing import Any

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.pattern_loader import load_presidio_entity_map
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.optional.presidio import get_analyzer_engine_class
from unplug.scanners.base import BaseScanner

_logger = logging.getLogger("unplug.pii")

_DEFAULT_CONFIG = default_scanner_config("pii")
_MIN_SCORE = 0.35


class PresidioPiiScanner(BaseScanner):
    """Microsoft Presidio analyzer for PII beyond regex (names, IBAN, passports, etc.)."""

    name = "pii"

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
        *,
        language: str = "en",
        min_score: float = _MIN_SCORE,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._language = language
        self._min_score = min_score
        self._analyzer: Any | None = None

    def _analyzer_engine(self) -> Any:
        if self._analyzer is None:
            analyzer_cls = get_analyzer_engine_class()
            self._analyzer = analyzer_cls()
        return self._analyzer

    def _should_scan(self, text: TaintedText) -> bool:
        return text.trust_level not in (TrustLevel.USER, TrustLevel.TRUSTED)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        try:
            results = self._analyzer_engine().analyze(
                text=text.text,
                language=self._language,
                score_threshold=self._min_score,
            )
        except Exception as exc:
            _logger.error("presidio analyze failed: %s", exc)
            yield Finding(
                category=self.name,
                subcategory="scanner_error",
                stage="error",
                span_start=0,
                span_end=len(text.text),
                score=1.0,
                evidence=f"Presidio failed: {type(exc).__name__}",
            )
            return

        seen: set[tuple[int, int, str]] = set()
        entity_map = load_presidio_entity_map()
        for hit in results:
            mapped = entity_map.get(hit.entity_type)
            if mapped is None:
                continue
            subcategory, base_score = mapped
            span_start, span_end = int(hit.start), int(hit.end)
            if span_end <= span_start:
                continue
            key = (span_start, span_end, subcategory)
            if key in seen:
                continue
            seen.add(key)
            score = min(1.0, base_score * float(hit.score))
            yield Finding(
                category="leakage",
                subcategory=subcategory,
                stage="presidio",
                span_start=span_start,
                span_end=span_end,
                score=score,
                evidence=f"Presidio detected {hit.entity_type}",
                replacement=None,
            )
