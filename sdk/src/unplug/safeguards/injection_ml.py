"""ML span injection scanner — BIOES checkpoint on normalized text."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.models import ModelProvider
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.safeguards.base import ModelScanner

_DEFAULT_CONFIG = ScannerConfig(base_score=0.85, enabled=True, normalize=True)


class InjectionSpanScanner(ModelScanner):
    """Fine-tuned span model — runs after regex when pipeline risk is below block threshold."""

    name = "injection_ml"

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
        model: ModelProvider | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics, model=model)
        self._normalizer = Normalizer()

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        if self._model.loaded is False:
            self._model.load()

        norm = self._normalizer.normalize(text.text)
        prediction = self._model.predict(norm.text)
        cfg = self._model.spec.config
        doc_threshold = float(cfg.get("doc_threshold", cfg.get("inj_threshold", 0.5)))

        for span in prediction.spans:
            orig_start, orig_end = norm.to_original_span(span.start, span.end)
            if orig_end <= orig_start:
                continue
            yield Finding(
                category="injection",
                subcategory="span_model",
                stage="model",
                span_start=orig_start,
                span_end=orig_end,
                score=max(span.score, self._config.base_score * 0.5),
                evidence="Span model flagged injection region",
                replacement="[BLOCKED:injection]",
            )

        if (
            not prediction.spans
            and prediction.doc_score >= doc_threshold
            and prediction.doc_score_source == "doc_head"
        ):
            yield Finding(
                category="injection",
                subcategory="doc_head",
                stage="model",
                span_start=0,
                span_end=len(text.text),
                score=max(prediction.doc_score, self._config.base_score * 0.5),
                evidence="Document classifier flagged injection",
                replacement="[BLOCKED:injection]",
            )
