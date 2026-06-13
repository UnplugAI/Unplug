"""Disposition head: separate injection from harmful-not-injection (v132 follow-up)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class DispositionLabel(StrEnum):
    BENIGN = "benign"
    INJECTION = "injection"
    HARMFUL_NOT_INJECTION = "harmful_not_injection"


class DispositionPrediction(BaseModel):
    model_config = {"frozen": True}

    label: DispositionLabel
    score: float = Field(ge=0.0, le=1.0)
    evidence: str = ""


class DualHeadWithDisposition(BaseModel):
    """Target v132 model outputs (training not yet wired)."""

    model_config = {"frozen": True}

    doc_injection_score: float = Field(ge=0.0, le=1.0)
    span_injection_score: float = Field(ge=0.0, le=1.0)
    disposition: DispositionPrediction

    def should_block_injection(self, *, tau_doc: float, tau_span: float) -> bool:
        if self.disposition.label == DispositionLabel.HARMFUL_NOT_INJECTION:
            return False
        if self.disposition.label == DispositionLabel.BENIGN:
            return False
        return self.disposition.label == DispositionLabel.INJECTION


def resolve_disposition(
    *,
    doc_injection_score: float,
    harmful_score: float,
    span_injection_score: float = 0.0,
    tau_harmful: float = 0.7,
    tau_injection: float = 0.45,
    tau_span: float = 0.5,
) -> DispositionPrediction:
    """Heuristic placeholder until the contrast head is trained.

    Span hits are direct injection evidence and win outright. Without spans, a
    high harmful signal is the better explanation for the doc head firing
    (harmful-not-injection contrast), even when the doc score itself is high.
    """
    if span_injection_score >= tau_span:
        return DispositionPrediction(
            label=DispositionLabel.INJECTION,
            score=span_injection_score,
            evidence="Span-level injection evidence",
        )
    if harmful_score >= tau_harmful:
        return DispositionPrediction(
            label=DispositionLabel.HARMFUL_NOT_INJECTION,
            score=harmful_score,
            evidence="High harmful signal without injection span evidence",
        )
    if doc_injection_score >= tau_injection:
        return DispositionPrediction(
            label=DispositionLabel.INJECTION,
            score=doc_injection_score,
            evidence="Injection doc signal",
        )
    return DispositionPrediction(
        label=DispositionLabel.BENIGN,
        score=1.0 - max(doc_injection_score, harmful_score),
        evidence="Below injection and harmful thresholds",
    )
