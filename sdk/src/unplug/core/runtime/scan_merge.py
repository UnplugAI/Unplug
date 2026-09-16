"""Merge ScanResults from multiple pipelines (fail-closed)."""

from __future__ import annotations

from unplug.api.enums import Action
from unplug.api.types import Finding, ScanResult

# Keep aligned with Guard._ACTION_SEVERITY (server canary overlay).
_ACTION_RANK: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.ABSTAIN: 1,
    Action.REVIEW: 2,
    Action.REDACT: 3,
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
    by_key: dict[tuple[str, str, int, int], Finding] = {}
    for result in results:
        for finding in result.findings:
            key = (
                finding.category,
                finding.subcategory,
                finding.span_start,
                finding.span_end,
            )
            existing = by_key.get(key)
            # Prefer higher score (and a defined replacement) so a weak/spoofed
            # remote hit cannot suppress an authoritative local registry/canary finding.
            if (
                existing is None
                or finding.score > existing.score
                or (
                    finding.score == existing.score
                    and existing.replacement is None
                    and finding.replacement is not None
                )
            ):
                by_key[key] = finding
    findings = list(by_key.values())

    action = max((r.action for r in results), key=lambda a: _ACTION_RANK[a])
    risk_score = max(
        max(r.risk_score for r in results),
        max((f.score for f in findings), default=0.0),
    )
    # Fail closed: only ALLOW (+ all parts safe) is safe. REDACT/REVIEW/ABSTAIN
    # must not inherit safe=True from a buggy or spoofed remote result.
    safe = action == Action.ALLOW and all(r.safe for r in results)

    # Last non-None wins. Call sites must scan later pipelines on the prior
    # redacted base (input → output) so this composes rather than overwriting
    # with a parallel view of the original text.
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
