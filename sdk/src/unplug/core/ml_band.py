"""ML dual-head decision band: ALLOW, ABSTAIN, or BLOCK."""

from __future__ import annotations

from enum import StrEnum

ML_ABSTAIN_SUBCATEGORY = "ml_abstain_band"


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


def decide_ml_band(
    *,
    doc_score: float,
    span_score: float,
    tau_doc: float,
    tau_span: float,
    tau_abstain_low: float,
) -> MlBand:
    """Three-way band aligned with unplug_exp v122 decision policy."""
    if doc_score >= tau_doc or span_score >= tau_span:
        return MlBand.BLOCK
    if doc_score < tau_abstain_low and span_score < tau_span:
        return MlBand.ALLOW
    return MlBand.ABSTAIN
