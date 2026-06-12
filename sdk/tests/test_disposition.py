"""Tests for disposition head placeholder logic."""

from __future__ import annotations

from unplug.core.disposition import (
    DispositionLabel,
    DispositionPrediction,
    DualHeadWithDisposition,
    resolve_disposition,
)


def test_harmful_not_injection() -> None:
    pred = resolve_disposition(doc_injection_score=0.2, harmful_score=0.9)
    assert pred.label == DispositionLabel.HARMFUL_NOT_INJECTION


def test_injection() -> None:
    pred = resolve_disposition(doc_injection_score=0.8, harmful_score=0.9)
    assert pred.label == DispositionLabel.INJECTION


def test_benign() -> None:
    pred = resolve_disposition(doc_injection_score=0.1, harmful_score=0.1)
    assert pred.label == DispositionLabel.BENIGN


def test_injection_label_blocks_below_caller_tau() -> None:
    head = DualHeadWithDisposition(
        doc_injection_score=0.46,
        span_injection_score=0.1,
        disposition=DispositionPrediction(
            label=DispositionLabel.INJECTION,
            score=0.46,
            evidence="injection",
        ),
    )
    assert head.should_block_injection(tau_doc=0.5, tau_span=0.45) is True


def test_harmful_not_injection_does_not_block() -> None:
    head = DualHeadWithDisposition(
        doc_injection_score=0.2,
        span_injection_score=0.1,
        disposition=DispositionPrediction(
            label=DispositionLabel.HARMFUL_NOT_INJECTION,
            score=0.9,
            evidence="harmful",
        ),
    )
    assert head.should_block_injection(tau_doc=0.5, tau_span=0.45) is False


def test_benign_does_not_block() -> None:
    head = DualHeadWithDisposition(
        doc_injection_score=0.1,
        span_injection_score=0.1,
        disposition=DispositionPrediction(
            label=DispositionLabel.BENIGN,
            score=0.9,
            evidence="ok",
        ),
    )
    assert head.should_block_injection(tau_doc=0.5, tau_span=0.45) is False
