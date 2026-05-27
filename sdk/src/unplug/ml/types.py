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
