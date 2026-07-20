"""BIOES decoder edge cases and happy paths."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from unplug.ml.bioes import decode_bioes_spans  # noqa: E402

pytestmark = pytest.mark.requires_ml


def test_decode_bioes_empty_without_inj_labels() -> None:
    label2id = {"O": 0, "B-PER": 1, "I-PER": 2}
    id2label = {v: k for k, v in label2id.items()}
    offset_mapping = [(0, 0), (0, 4), (4, 8), (0, 0)]
    probs = torch.softmax(torch.randn(4, 3), dim=-1)
    spans = decode_bioes_spans(
        offset_mapping,
        probs=probs,
        id2label=id2label,
        label2id=label2id,
        inj_threshold=0.5,
    )
    assert spans == []


def test_decode_bioes_single_token_s_tag() -> None:
    label2id = {"O": 0, "B-INJ": 1, "I-INJ": 2, "E-INJ": 3, "S-INJ": 4}
    id2label = {v: k for k, v in label2id.items()}
    offset_mapping = [(0, 0), (0, 5), (0, 0)]
    logits = torch.tensor(
        [
            [10.0, 0.0, 0.0, 0.0, 0.0],
            [0.0, 0.0, 0.0, 0.0, 10.0],
            [10.0, 0.0, 0.0, 0.0, 0.0],
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
    assert spans[0].end == 5


def test_decode_bioes_b_i_e_span() -> None:
    label2id = {"O": 0, "B-INJ": 1, "I-INJ": 2, "E-INJ": 3, "S-INJ": 4}
    id2label = {v: k for k, v in label2id.items()}
    offset_mapping = [(0, 0), (0, 3), (3, 7), (7, 11), (0, 0)]
    logits = torch.tensor(
        [
            [10.0, 0.0, 0.0, 0.0, 0.0],
            [0.0, 10.0, 0.0, 0.0, 0.0],
            [0.0, 0.0, 10.0, 0.0, 0.0],
            [0.0, 0.0, 0.0, 10.0, 0.0],
            [10.0, 0.0, 0.0, 0.0, 0.0],
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
