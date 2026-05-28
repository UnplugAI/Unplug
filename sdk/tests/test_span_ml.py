"""Tests for BIOES span decoding."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from unplug.ml.bioes import decode_bioes_spans  # noqa: E402


def test_decode_bioes_single_span() -> None:
    label2id = {"O": 0, "B-INJ": 1, "I-INJ": 2}
    id2label = {v: k for k, v in label2id.items()}
    offset_mapping = [(0, 0), (0, 5), (5, 11), (0, 0)]
    logits = torch.tensor(
        [
            [10.0, 0.0, 0.0],
            [0.0, 10.0, 0.0],
            [0.0, 0.0, 10.0],
            [10.0, 0.0, 0.0],
        ]
    )
    probs = torch.softmax(logits, dim=-1)
    spans = decode_bioes_spans(
        offset_mapping,
        probs=probs,
        id2label=id2label,
        label2id=label2id,
        inj_threshold=0.5,
    )
    assert len(spans) == 1
    assert spans[0].start == 0
    assert spans[0].end == 11


def test_decode_bioes_respects_threshold() -> None:
    label2id = {"O": 0, "B-INJ": 1, "I-INJ": 2}
    id2label = {v: k for k, v in label2id.items()}
    offset_mapping = [(0, 0), (0, 4), (0, 0)]
    logits = torch.tensor(
        [
            [10.0, 0.0, 0.0],
            [2.0, 1.0, 0.0],
            [10.0, 0.0, 0.0],
        ]
    )
    probs = torch.softmax(logits, dim=-1)
    spans = decode_bioes_spans(
        offset_mapping,
        probs=probs,
        id2label=id2label,
        label2id=label2id,
        inj_threshold=0.9,
    )
    assert spans == []
