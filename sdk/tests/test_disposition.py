"""Tests for disposition head placeholder logic."""

from __future__ import annotations

from unplug.core.disposition import DispositionLabel, resolve_disposition


def test_harmful_not_injection() -> None:
    pred = resolve_disposition(doc_injection_score=0.2, harmful_score=0.9)
    assert pred.label == DispositionLabel.HARMFUL_NOT_INJECTION


def test_injection() -> None:
    pred = resolve_disposition(doc_injection_score=0.8, harmful_score=0.9)
    assert pred.label == DispositionLabel.INJECTION


def test_benign() -> None:
    pred = resolve_disposition(doc_injection_score=0.1, harmful_score=0.1)
    assert pred.label == DispositionLabel.BENIGN
