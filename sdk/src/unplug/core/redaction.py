"""Span redaction — BLOCKED tags, strip, legacy REDACTED, or none."""

from __future__ import annotations

from unplug.api.types import Finding
from unplug.config.policy import RedactionMode, ScanPolicy


def format_replacement(finding: Finding, mode: RedactionMode) -> str:
    """Resolve placeholder text for a flagged span."""
    if mode == RedactionMode.STRIP:
        return ""
    if mode == RedactionMode.REDACTED_TAGS:
        if finding.replacement is not None:
            return finding.replacement
        return f"[REDACTED:{finding.category}]"
    if mode == RedactionMode.BLOCKED_TAGS:
        return f"[BLOCKED:{finding.category}]"
    return ""


def apply_span_redactions(text: str, findings: list[Finding], policy: ScanPolicy) -> str | None:
    """Apply span replacements for findings at or above redact_threshold."""
    if policy.redaction_mode == RedactionMode.NONE:
        return None

    raw_spans: list[tuple[int, int, str]] = []
    for finding in findings:
        if finding.score < policy.redact_threshold:
            continue
        if finding.span_end <= finding.span_start:
            continue
        repl = format_replacement(finding, policy.redaction_mode)
        raw_spans.append((finding.span_start, finding.span_end, repl))

    if not raw_spans:
        return text

    raw_spans.sort(key=lambda s: s[0])
    merged: list[tuple[int, int, str]] = []
    for start, end, repl in raw_spans:
        if merged and start <= merged[-1][1]:
            prev_start, prev_end, prev_repl = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end), prev_repl)
        else:
            merged.append((start, end, repl))

    result = text
    for start, end, replacement in reversed(merged):
        result = result[:start] + replacement + result[end:]
    return result
