"""Shared types for span ML inference."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CharSpan:
    start: int
    end: int
    score: float = 1.0
    category: str = "injection"


@dataclass(frozen=True)
class SpanPrediction:
    text_normalized: str
    spans: list[CharSpan]
    # Document-level injection probability (dual-head doc head, or max token INJ prob).
    doc_score: float = 0.0
    doc_score_source: str = "token_max"
    # v132 ternary checkpoints expose a disposition head
    # (benign | injection | harmful_not_injection). None on older checkpoints,
    # in which case the heuristic in core.disposition is the fallback.
    disposition_label: str | None = None
    disposition_probs: dict[str, float] | None = None
