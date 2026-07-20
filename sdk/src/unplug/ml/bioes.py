"""BIOES token-tag decoding for injection spans."""

from __future__ import annotations

from unplug.ml.types import CharSpan


def decode_bioes_spans(
    offset_mapping: list[tuple[int, int]],
    *,
    probs: object,
    id2label: dict[int, str],
    label2id: dict[str, int],
    inj_threshold: float,
) -> list[CharSpan]:
    """Decode BIO or true BIOES tags into character spans.

    Handles B/I and, when present in the label map, E (explicit end) and
    S (single token). Falls back to plain BIO behavior for BIO-only checkpoints.

    Returns an empty list when the label map has no ``*-INJ`` columns (callers
    should reject such checkpoints at load time).
    """
    inj_cols = [label2id[t] for t in ("B-INJ", "I-INJ", "E-INJ", "S-INJ") if t in label2id]
    if not inj_cols:
        return []
    inj_label_ids = set(inj_cols)
    current: CharSpan | None = None
    spans: list[CharSpan] = []

    for idx, (start, end) in enumerate(offset_mapping):
        if start == end == 0:
            continue
        pred_id = int(probs[idx].argmax().item())  # type: ignore[union-attr]
        tag = id2label.get(pred_id, "O")
        inj_score = max(float(probs[idx][col].item()) for col in inj_cols)  # type: ignore[index]
        is_inj = pred_id in inj_label_ids and inj_score >= inj_threshold

        if not is_inj:
            if current is not None:
                spans.append(current)
                current = None
            continue

        if tag.startswith("S-"):
            if current is not None:
                spans.append(current)
            spans.append(CharSpan(start=start, end=end, score=inj_score))
            current = None
        elif tag.startswith("B-"):
            if current is not None:
                spans.append(current)
            current = CharSpan(start=start, end=end, score=inj_score)
        elif tag.startswith(("I-", "E-")):
            if current is None:
                current = CharSpan(start=start, end=end, score=inj_score)
            else:
                current = CharSpan(
                    start=current.start,
                    end=end,
                    score=max(current.score, inj_score),
                    category=current.category,
                )
            if tag.startswith("E-"):
                spans.append(current)
                current = None

    if current is not None:
        spans.append(current)
    return spans
