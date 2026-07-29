"""Tests for fail-closed ScanResult merging."""

from __future__ import annotations

import pytest

from unplug.api.enums import Action
from unplug.api.types import Finding, ScanResult
from unplug.core.runtime.scan_merge import merge_scan_results


def _result(
    *,
    action: Action = Action.ALLOW,
    safe: bool = True,
    findings: list[Finding] | None = None,
    risk_score: float = 0.0,
    redacted_text: str | None = None,
    latency_ms: float = 1.0,
) -> ScanResult:
    return ScanResult(
        safe=safe,
        action=action,
        risk_score=risk_score,
        findings=findings or [],
        redacted_text=redacted_text,
        latency_ms=latency_ms,
        stages_run=[f.category for f in (findings or [])],
    )


def test_merge_empty_raises() -> None:
    with pytest.raises(ValueError, match="at least one"):
        merge_scan_results()


def test_merge_single_identity() -> None:
    only = _result(action=Action.BLOCK, safe=False, risk_score=0.9)
    assert merge_scan_results(only) is only


def test_merge_worst_action_and_findings() -> None:
    inj = Finding(
        category="injection",
        subcategory="ignore_previous",
        stage="regex",
        span_start=0,
        span_end=10,
        score=0.85,
        evidence="injection",
    )
    secret = Finding(
        category="secrets",
        subcategory="registered_secret:INTERNAL",
        stage="registry",
        span_start=5,
        span_end=20,
        score=1.0,
        evidence="secret",
    )
    merged = merge_scan_results(
        _result(action=Action.REDACT, safe=True, findings=[inj], risk_score=0.85, latency_ms=2.0),
        _result(
            action=Action.BLOCK,
            safe=False,
            findings=[secret],
            risk_score=1.0,
            redacted_text="redacted",
            latency_ms=3.0,
        ),
    )
    assert merged.action == Action.BLOCK
    assert merged.safe is False
    assert merged.risk_score == 1.0
    assert len(merged.findings) == 2
    assert merged.redacted_text == "redacted"
    assert merged.latency_ms == 5.0
