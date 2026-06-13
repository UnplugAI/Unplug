"""Coverage-based policy decisions."""

from __future__ import annotations

from unplug.api.enums import Action
from unplug.api.types import Finding
from unplug.config.policy import RedactionMode, ScanPolicy
from unplug.core.policy.decision import ML_ABSTAIN_SUBCATEGORY


def merge_spans(spans: list[tuple[int, int]], *, merge: bool) -> list[tuple[int, int]]:
    if not spans or not merge:
        return spans
    ordered = sorted(spans, key=lambda s: s[0])
    merged: list[tuple[int, int]] = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def flagged_coverage(text_len: int, findings: list[Finding], policy: ScanPolicy) -> float:
    if text_len <= 0:
        return 0.0
    spans = [
        (f.span_start, f.span_end)
        for f in findings
        if f.score >= policy.redact_threshold and f.span_end > f.span_start
    ]
    merged = merge_spans(spans, merge=policy.merge_overlapping_spans)
    covered = sum(end - start for start, end in merged)
    return min(1.0, covered / text_len)


def policy_from_request(request: object, default: ScanPolicy) -> ScanPolicy:
    """Merge optional ScanRequest policy overrides into defaults."""
    overrides: dict[str, float | bool | RedactionMode] = {}
    for field in (
        "block_coverage_ratio",
        "redact_threshold",
        "review_threshold",
        "block_threshold",
    ):
        value = getattr(request, field, None)
        if value is not None:
            overrides[field] = value

    redaction_mode = getattr(request, "redaction_mode", None)
    if redaction_mode is not None:
        overrides["redaction_mode"] = redaction_mode

    redact = getattr(request, "redact", True)
    if redact is False:
        overrides["redaction_mode"] = RedactionMode.NONE

    if not overrides:
        return default
    return default.model_copy(update=overrides)


def decide_action(
    findings: list[Finding],
    *,
    text_len: int,
    policy: ScanPolicy,
    risk_score: float,
) -> Action:
    """Apply document coverage gate then span-level thresholds."""
    if text_len > 0 and flagged_coverage(text_len, findings, policy) >= policy.block_coverage_ratio:
        return Action.BLOCK
    if risk_score >= policy.block_threshold:
        return Action.BLOCK
    if policy.abstain_enabled and any(f.subcategory == ML_ABSTAIN_SUBCATEGORY for f in findings):
        return Action.ABSTAIN
    if any(f.score >= policy.redact_threshold for f in findings):
        return Action.REDACT
    if risk_score >= policy.review_threshold:
        return Action.REVIEW
    return Action.ALLOW


def is_result_safe(action: Action, policy: ScanPolicy) -> bool:
    """Whether scan output is safe for downstream model/tool use."""
    return action == Action.ALLOW or (action == Action.ABSTAIN and policy.abstain_is_safe)
