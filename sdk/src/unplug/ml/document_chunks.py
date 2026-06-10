"""Overlapping document windows for full long-text ML coverage."""

from __future__ import annotations

from unplug.ml.spans_merge import merge_char_spans
from unplug.ml.types import CharSpan, SpanPrediction


def should_chunk_document(text_len: int, *, threshold_chars: int) -> bool:
    return text_len > threshold_chars


def split_sliding_windows(
    text: str,
    *,
    chunk_chars: int,
    overlap_chars: int,
) -> list[tuple[str, int]]:
    """Return (window_text, char_offset) pairs covering the full document."""
    if not text:
        return [("", 0)]
    chunk = max(64, chunk_chars)
    if len(text) <= chunk:
        return [(text, 0)]

    overlap = max(0, min(overlap_chars, chunk - 1))
    step = max(1, chunk - overlap)
    windows: list[tuple[str, int]] = []
    start = 0
    while start < len(text):
        end = min(start + chunk, len(text))
        windows.append((text[start:end], start))
        if end >= len(text):
            break
        start += step
    return windows


def merge_window_predictions(
    window_preds: list[tuple[int, SpanPrediction]],
    *,
    full_text: str,
) -> SpanPrediction:
    """Shift per-window spans onto full-text coordinates and merge overlaps."""
    all_spans: list[CharSpan] = []
    doc_score = 0.0
    doc_source = "token_max"

    for offset, pred in window_preds:
        all_spans.extend(
            CharSpan(
                start=span.start + offset,
                end=span.end + offset,
                score=span.score,
                category=span.category,
            )
            for span in pred.spans
        )
        if pred.doc_score > doc_score:
            doc_score = pred.doc_score
            doc_source = pred.doc_score_source
        elif pred.doc_score == doc_score and pred.doc_score_source == "doc_head":
            doc_source = "doc_head"

    return SpanPrediction(
        text_normalized=full_text,
        spans=merge_char_spans(all_spans),
        doc_score=doc_score,
        doc_score_source=doc_source,
    )
