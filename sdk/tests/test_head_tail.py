"""Tests for head/tail ML chunking."""

from __future__ import annotations

from unplug.ml.head_tail import merge_head_tail_predictions, should_use_head_tail, split_head_tail
from unplug.ml.types import CharSpan, SpanPrediction


class TestHeadTailSplit:
    def test_short_text_no_split_needed(self) -> None:
        assert should_use_head_tail(100, threshold_chars=8192) is False

    def test_long_text_uses_head_tail(self) -> None:
        assert should_use_head_tail(9000, threshold_chars=8192) is True

    def test_split_returns_tail_offset(self) -> None:
        text = "A" * 5000
        head, tail, offset = split_head_tail(text, chunk_chars=2048)
        assert len(head) == 2048
        assert len(tail) == 2048
        assert offset == 5000 - 2048
        assert text[:2048] == head
        assert text[offset:] == tail


class TestHeadTailMerge:
    def test_merges_tail_spans_with_offset(self) -> None:
        head_pred = SpanPrediction(
            text_normalized="head",
            spans=[CharSpan(start=1, end=3, score=0.9)],
            doc_score=0.1,
            doc_score_source="token_max",
        )
        tail_pred = SpanPrediction(
            text_normalized="tail",
            spans=[CharSpan(start=2, end=5, score=0.8)],
            doc_score=0.95,
            doc_score_source="doc_head",
        )
        full = "x" * 100
        merged = merge_head_tail_predictions(
            head_pred,
            tail_pred,
            tail_offset=80,
            full_text=full,
        )
        assert len(merged.spans) == 2
        assert merged.spans[1].start == 82
        assert merged.doc_score == 0.95
        assert merged.doc_score_source == "doc_head"
