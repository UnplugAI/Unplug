"""Helpers to rebuild ScanResult after extra findings (privacy filter, etc.)."""

from __future__ import annotations

from unplug.api.types import Finding, ScanResult
from unplug.config.policy import ScanPolicy
from unplug.core.policy import decide_action, is_result_safe


def refresh_scan_result(
    text: str,
    findings: list[Finding],
    *,
    baseline: ScanResult,
    policy: ScanPolicy,
) -> ScanResult:
    risk_score = max((f.score for f in findings), default=0.0)
    action = decide_action(
        findings,
        text_len=len(text),
        policy=policy,
        risk_score=risk_score,
    )
    stages = list(dict.fromkeys([*baseline.stages_run, *(f.stage for f in findings)]))
    return ScanResult(
        safe=is_result_safe(action, policy),
        action=action,
        risk_score=risk_score,
        findings=findings,
        redacted_text=baseline.redacted_text,
        latency_ms=baseline.latency_ms,
        stages_run=stages,
    )
