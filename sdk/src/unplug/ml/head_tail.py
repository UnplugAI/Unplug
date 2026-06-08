"""Head/tail chunking for long-text ML scans (LLM Guard pattern)."""

from __future__ import annotations

from unplug.ml.spans_merge import merge_char_spans
from unplug.ml.types import CharSpan, SpanPrediction


def should_use_head_tail(text_len: int, *, threshold_chars: int) -> bool:
    return text_len > threshold_chars


def split_head_tail(text: str, *, chunk_chars: int) -> tuple[str, str, int]:
    """Return head text, tail text, and character offset where tail begins."""
    chunk = max(64, chunk_chars)
    if len(text) <= chunk * 2:
        mid = len(text) // 2
        return text[:mid], text[mid:], mid
    tail_offset = len(text) - chunk
    return text[:chunk], text[tail_offset:], tail_offset


def merge_head_tail_predictions(
    head: SpanPrediction,
    tail: SpanPrediction,
    *,
    tail_offset: int,
    full_text: str,
) -> SpanPrediction:
    """Merge span predictions from head and tail windows onto full text coordinates."""
    shifted_tail = [
        CharSpan(
            start=span.start + tail_offset,
            end=span.end + tail_offset,
            score=span.score,
            category=span.category,
        )
        for span in tail.spans
    ]
    merged_spans = merge_char_spans([*head.spans, *shifted_tail])

    doc_score = max(head.doc_score, tail.doc_score)
    if head.doc_score >= tail.doc_score:
        doc_source = head.doc_score_source
    else:
        doc_source = tail.doc_score_source

    return SpanPrediction(
        text_normalized=full_text,
        spans=merged_spans,
        doc_score=doc_score,
        doc_score_source=doc_source,
    )
