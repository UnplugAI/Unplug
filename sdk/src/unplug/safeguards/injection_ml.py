"""ML span injection scanner — BIOES checkpoint on normalized text."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.decision import (
    ML_ABSTAIN_SUBCATEGORY,
    DecisionMode,
    DecisionPolicy,
    MlBand,
    decide_band,
    max_span_score,
)
from unplug.core.disposition import DispositionLabel, resolve_disposition
from unplug.core.models import ModelProvider
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.ml.document_chunks import (
    merge_window_predictions,
    should_chunk_document,
    split_sliding_windows,
)
from unplug.ml.head_tail import merge_head_tail_predictions, split_head_tail
from unplug.models import Finding
from unplug.safeguards.base import ModelScanner
from unplug.safeguards.harmful import harmful_signal

_DEFAULT_CONFIG = ScannerConfig(base_score=0.85, enabled=True, normalize=True)

# Defaults — override via ModelSpec.config (head_tail_enabled, head_tail_threshold_chars, …).
_DEFAULT_HEAD_TAIL_THRESHOLD = 8192
_DEFAULT_HEAD_TAIL_CHUNK = 2048


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

    def _predict(self, norm_text: str):
        cfg = self._model.spec.config
        threshold = int(
            cfg.get(
                "long_text_threshold_chars",
                cfg.get("head_tail_threshold_chars", _DEFAULT_HEAD_TAIL_THRESHOLD),
            )
        )
        chunk = int(
            cfg.get(
                "long_text_chunk_chars",
                cfg.get("head_tail_chunk_chars", _DEFAULT_HEAD_TAIL_CHUNK),
            )
        )
        if not should_chunk_document(len(norm_text), threshold_chars=threshold):
            return self._model.predict(norm_text)

        mode = str(cfg.get("long_text_mode", "sliding"))
        if mode == "head_tail" and bool(cfg.get("head_tail_enabled", True)):
            head, tail, tail_offset = split_head_tail(norm_text, chunk_chars=chunk)
            head_pred = self._model.predict(head)
            tail_pred = self._model.predict(tail)
            return merge_head_tail_predictions(
                head_pred,
                tail_pred,
                tail_offset=tail_offset,
                full_text=norm_text,
            )

        overlap = int(cfg.get("long_text_overlap_chars", 256))
        windows = split_sliding_windows(norm_text, chunk_chars=chunk, overlap_chars=overlap)
        window_texts = [text for text, _ in windows]
        predictions = list(self._model.predict_batch(window_texts))
        window_preds = [
            (offset, pred) for (_, offset), pred in zip(windows, predictions, strict=True)
        ]
        return merge_window_predictions(window_preds, full_text=norm_text)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        if self._model.loaded is False:
            self._model.load()

        norm = self._normalizer.normalize(text.text)
        prediction = self._predict(norm.text)
        cfg = self._model.spec.config
        policy = context.scan_policy
        doc_threshold = float(cfg.get("doc_threshold", cfg.get("inj_threshold", 0.5)))
        span_threshold = float(cfg.get("inj_threshold", 0.5))
        decision = DecisionPolicy(
            mode=(
                policy.decision_mode
                if policy is not None
                else DecisionMode(str(cfg.get("decision_mode", DecisionMode.DOC_OR_SPAN)))
            ),
            tau_doc=doc_threshold,
            tau_span=span_threshold,
            tau_doc_gate=(
                policy.tau_doc_gate if policy is not None else float(cfg.get("tau_doc_gate", 0.99))
            ),
            tau_abstain_low=(
                policy.tau_abstain_low
                if policy is not None
                else float(cfg.get("tau_abstain_low", 0.35))
            ),
            abstain_enabled=(
                policy.abstain_enabled
                if policy is not None
                else bool(cfg.get("abstain_enabled", True))
            ),
        )
        span_score = max_span_score(list(prediction.spans))
        band = decide_band(
            doc_score=float(prediction.doc_score),
            span_score=span_score,
            policy=decision,
        )

        if band == MlBand.ALLOW:
            return

        # Doc-only signal (no span evidence) on harmful-looking text is the
        # harmful-not-injection contrast: leave it to the harmful scanner.
        # v132 checkpoints carry a trained disposition head; the regex-based
        # heuristic remains the fallback for older checkpoints.
        harmful_not_injection = False
        if not prediction.spans:
            if prediction.disposition_probs is not None:
                disposition_threshold = float(cfg.get("disposition_threshold", 0.5))
                harmful_not_injection = (
                    prediction.disposition_probs.get("harmful_not_injection", 0.0)
                    >= disposition_threshold
                )
            else:
                disposition = resolve_disposition(
                    doc_injection_score=float(prediction.doc_score),
                    harmful_score=harmful_signal(norm.text),
                    span_injection_score=span_score,
                    tau_injection=doc_threshold,
                    tau_span=span_threshold,
                )
                harmful_not_injection = disposition.label is DispositionLabel.HARMFUL_NOT_INJECTION

        if band == MlBand.ABSTAIN:
            if harmful_not_injection:
                return
            yield Finding(
                category="injection",
                subcategory=ML_ABSTAIN_SUBCATEGORY,
                stage="ml_band",
                span_start=0,
                span_end=0,
                score=max(float(prediction.doc_score), span_score, 0.55),
                evidence="ML abstain band: uncertain injection signal",
                replacement="[REDACTED:injection]",
            )
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
                    score=max(span.score, 0.55),
                    evidence="Span model flagged uncertain injection region",
                    replacement="[REDACTED:injection]",
                )
            return

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
            and not harmful_not_injection
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
