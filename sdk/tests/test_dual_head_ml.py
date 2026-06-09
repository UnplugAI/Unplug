"""Tests for dual-head SpanPrediction fields and token-max fallback."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from unplug.ml.span_model import _token_max_inj_prob  # noqa: E402
from unplug.ml.types import SpanPrediction  # noqa: E402


def test_span_prediction_doc_fields_default() -> None:
    pred = SpanPrediction(text_normalized="hello", spans=[])
    assert pred.doc_score == 0.0
    assert pred.doc_score_source == "token_max"


def test_token_max_inj_prob_picks_highest_inj_token() -> None:
    label2id = {"O": 0, "B-INJ": 1, "I-INJ": 2}
    offset_mapping = [(0, 0), (0, 4), (4, 8), (0, 0)]
    logits = torch.tensor(
        [
            [10.0, 0.0, 0.0],
            [0.0, 10.0, 0.0],
            [0.0, 0.0, 10.0],
            [10.0, 0.0, 0.0],
        ]
    )
    probs = torch.softmax(logits, dim=-1)
    score = _token_max_inj_prob(offset_mapping, probs=probs, label2id=label2id)
    assert score > 0.9
