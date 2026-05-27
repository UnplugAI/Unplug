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
    inj_label_ids = {
        label2id.get("B-INJ", -1),
        label2id.get("I-INJ", -1),
    }
    current: CharSpan | None = None
    spans: list[CharSpan] = []

    for idx, (start, end) in enumerate(offset_mapping):
        if start == end == 0:
            continue
        pred_id = int(probs[idx].argmax().item())  # type: ignore[union-attr]
        tag = id2label.get(pred_id, "O")
        inj_score = max(
            float(probs[idx][label2id["B-INJ"]].item()),  # type: ignore[index]
            float(probs[idx][label2id["I-INJ"]].item()),  # type: ignore[index]
        )
        is_inj = pred_id in inj_label_ids and inj_score >= inj_threshold

        if is_inj and tag.startswith("B-"):
            if current is not None:
                spans.append(current)
            current = CharSpan(start=start, end=end, score=inj_score)
        elif is_inj and tag.startswith("I-") and current is not None:
            current = CharSpan(
                start=current.start,
                end=end,
                score=max(current.score, inj_score),
                category=current.category,
            )
        else:
            if current is not None:
                spans.append(current)
                current = None

    if current is not None:
        spans.append(current)
    return spans
