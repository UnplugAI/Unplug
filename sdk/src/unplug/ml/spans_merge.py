"""Merge overlapping character spans from sliding-window inference."""

from __future__ import annotations

from unplug.ml.types import CharSpan


def merge_char_spans(spans: list[CharSpan], *, gap: int = 0) -> list[CharSpan]:
    if not spans:
        return []
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    merged: list[CharSpan] = [ordered[0]]
    for span in ordered[1:]:
        prev = merged[-1]
        if span.start <= prev.end + gap:
            merged[-1] = CharSpan(
                start=prev.start,
                end=max(prev.end, span.end),
                score=max(prev.score, span.score),
                category=prev.category,
            )
        else:
            merged.append(span)
    return merged
