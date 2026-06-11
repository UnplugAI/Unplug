"""Tests for sliding-window document chunking."""

from __future__ import annotations

from unplug.ml.document_chunks import (
    merge_window_predictions,
    should_chunk_document,
    split_sliding_windows,
)
from unplug.ml.types import CharSpan, SpanPrediction


def test_short_text_single_window() -> None:
    windows = split_sliding_windows("short", chunk_chars=2048, overlap_chars=256)
    assert windows == [("short", 0)]


def test_sliding_windows_cover_full_document() -> None:
    text = "A" * 10_000
    windows = split_sliding_windows(text, chunk_chars=2048, overlap_chars=256)
    assert len(windows) > 2
    assert windows[0] == ("A" * 2048, 0)
    last_text, last_offset = windows[-1]
    assert last_offset + len(last_text) == len(text)
    assert text[last_offset:] == last_text


def test_should_chunk_document_threshold() -> None:
    assert should_chunk_document(100, threshold_chars=8192) is False
    assert should_chunk_document(9000, threshold_chars=8192) is True


def test_merge_window_predictions_shifts_spans() -> None:
    pred_a = SpanPrediction(
        text_normalized="aaa",
        spans=[CharSpan(start=1, end=2, score=0.9)],
        doc_score=0.2,
        doc_score_source="token_max",
    )
    pred_b = SpanPrediction(
        text_normalized="bbb",
        spans=[CharSpan(start=0, end=1, score=0.8)],
        doc_score=0.95,
        doc_score_source="doc_head",
    )
    full = "x" * 5000
    merged = merge_window_predictions([(0, pred_a), (3000, pred_b)], full_text=full)
    assert merged.spans[0].start == 1
    assert merged.spans[1].start == 3000
    assert merged.doc_score == 0.95
    assert merged.doc_score_source == "doc_head"
