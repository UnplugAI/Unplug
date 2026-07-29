"""Merge ScanResults from multiple pipelines (fail-closed)."""

from __future__ import annotations

from unplug.api.enums import Action
from unplug.api.types import Finding, ScanResult

_ACTION_RANK: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.REDACT: 1,
    Action.REVIEW: 2,
    Action.ABSTAIN: 3,
    Action.BLOCK: 4,
}


def merge_scan_results(*results: ScanResult) -> ScanResult:
    """Union findings and take the worst action; never upgrade a block to allow."""
    if not results:
        msg = "merge_scan_results requires at least one ScanResult"
        raise ValueError(msg)
    if len(results) == 1:
        return results[0]

    findings: list[Finding] = []
    seen: set[tuple[str, str, int, int]] = set()
    for result in results:
        for finding in result.findings:
            key = (
                finding.category,
                finding.subcategory,
                finding.span_start,
                finding.span_end,
            )
            if key in seen:
                continue
            findings.append(finding)
            seen.add(key)

    action = max((r.action for r in results), key=lambda a: _ACTION_RANK[a])
    risk_score = max(
        max(r.risk_score for r in results),
        max((f.score for f in findings), default=0.0),
    )
    safe = all(r.safe for r in results)
    if action in (Action.BLOCK, Action.REVIEW, Action.ABSTAIN):
        safe = False

    redacted: str | None = None
    for result in results:
        if result.redacted_text is not None:
            redacted = result.redacted_text

    stages: list[str] = []
    for result in results:
        for stage in result.stages_run:
            if stage not in stages:
                stages.append(stage)

    degraded_layers: list[str] = []
    for result in results:
        for layer in result.degraded_layers:
            if layer not in degraded_layers:
                degraded_layers.append(layer)

    approval = next((r.approval for r in results if r.approval is not None), None)

    return ScanResult(
        safe=safe,
        action=action,
        risk_score=risk_score,
        findings=findings,
        redacted_text=redacted,
        latency_ms=sum(r.latency_ms for r in results),
        stages_run=stages,
        degraded=any(r.degraded for r in results),
        degraded_layers=degraded_layers,
        approval=approval,
    )
