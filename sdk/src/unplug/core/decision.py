"""Unified ML decision policy — doc/span modes (unplug_exp parity) and abstain band."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from unplug.config.policy import DecisionMode, MlGateConfig

ML_ABSTAIN_SUBCATEGORY = "ml_abstain_band"

__all__ = [
    "ML_ABSTAIN_SUBCATEGORY",
    "DecisionMode",
    "DecisionPolicy",
    "MlBand",
    "decide_band",
    "decide_ml_band",
    "max_span_score",
    "should_invoke_ml",
]


class MlBand(StrEnum):
    ALLOW = "allow"
    ABSTAIN = "abstain"
    BLOCK = "block"


def max_span_score(spans: list[object]) -> float:
    best = 0.0
    for span in spans:
        score = float(getattr(span, "score", 0.0))
        best = max(best, score)
    return best


class DecisionPolicy(BaseModel):
    """Configurable doc/span decision — ported from unplug_exp lib/decision.py."""

    model_config = {"frozen": True}

    mode: DecisionMode = DecisionMode.DOC_OR_SPAN
    tau_doc: float = Field(default=0.95, ge=0.0, le=1.0)
    tau_span: float = Field(default=0.5, ge=0.0, le=1.0)
    tau_doc_gate: float = Field(
        default=0.99,
        ge=0.0,
        le=1.0,
        description=(
            "DOC_GATED: doc score alone (no span corroboration) detects only at/above "
            "this second, higher bar; values <= tau_doc make the gate a no-op"
        ),
    )
    tau_abstain_low: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Doc score below this (and no span fire) -> ALLOW band",
    )
    abstain_enabled: bool = True

    def doc_fires(self, doc_score: float) -> bool:
        return float(doc_score) >= self.tau_doc

    def span_fires(self, span_score: float) -> bool:
        return float(span_score) >= self.tau_span

    def is_detected(self, doc_score: float, span_score: float) -> bool:
        if self.mode == DecisionMode.DOC_ONLY:
            return self.doc_fires(doc_score)
        if self.mode == DecisionMode.DOC_GATED:
            if not self.doc_fires(doc_score):
                return False
            return self.span_fires(span_score) or float(doc_score) >= self.tau_doc_gate
        return self.doc_fires(doc_score) or self.span_fires(span_score)

    def score_for_calibration(self, doc_score: float, span_score: float) -> float:
        """Single scalar for threshold sweeps."""
        if self.mode == DecisionMode.DOC_ONLY:
            return float(doc_score)
        if self.mode == DecisionMode.DOC_GATED:
            if not self.doc_fires(doc_score):
                return 0.0
            if float(doc_score) >= self.tau_doc_gate:
                # Doc alone cleared the gate: the scalar must reflect the
                # signal that fired, not a possibly-low span score.
                return max(float(doc_score), float(span_score))
            return float(span_score)
        return max(float(doc_score), float(span_score))


def decide_band(*, doc_score: float, span_score: float, policy: DecisionPolicy) -> MlBand:
    """Three-way band: detection per policy mode, then ALLOW/ABSTAIN split below it."""
    if policy.is_detected(doc_score, span_score):
        return MlBand.BLOCK
    if not policy.abstain_enabled:
        return MlBand.ALLOW
    # DOC_ONLY ignores the span head for detection, so it must not let a
    # high span score push an otherwise-clean doc into the ABSTAIN band.
    span_holds = policy.mode != DecisionMode.DOC_ONLY and policy.span_fires(span_score)
    if doc_score < policy.tau_abstain_low and not span_holds:
        return MlBand.ALLOW
    return MlBand.ABSTAIN


def decide_ml_band(
    *,
    doc_score: float,
    span_score: float,
    tau_doc: float,
    tau_span: float,
    tau_abstain_low: float,
) -> MlBand:
    """DOC_OR_SPAN band aligned with unplug_exp v122 decision policy."""
    return decide_band(
        doc_score=doc_score,
        span_score=span_score,
        policy=DecisionPolicy(
            mode=DecisionMode.DOC_OR_SPAN,
            tau_doc=tau_doc,
            tau_span=tau_span,
            tau_abstain_low=tau_abstain_low,
        ),
    )


def should_invoke_ml(
    *,
    regex_risk: float,
    regex_flagged: bool,
    gate: MlGateConfig,
    block_threshold: float,
) -> bool:
    """Hybrid regex-to-ML routing (server semantic-layer pattern).

    Skip ML when regex already reached high confidence; below that, either
    always second-pass (default) or only in the gray band / on a regex flag.
    """
    gray_high = gate.gray_high if gate.gray_high is not None else block_threshold
    if regex_risk >= gray_high:
        return False
    if gate.always_below_high:
        return True
    if regex_flagged:
        return True
    return regex_risk >= gate.gray_low
