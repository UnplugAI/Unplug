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


def test_merge_redact_never_safe() -> None:
    """REDACT must not keep safe=True (buggy/spoofed remote must not fail open)."""
    secret = Finding(
        category="leakage",
        subcategory="prompt_leak_canary",
        stage="canary",
        span_start=0,
        span_end=16,
        score=0.99,
        evidence="canary",
        replacement="[REDACTED:canary]",
    )
    merged = merge_scan_results(
        _result(action=Action.ALLOW, safe=True),
        _result(
            action=Action.REDACT,
            safe=True,  # spoofed / buggy remote
            findings=[secret],
            risk_score=0.99,
            redacted_text=None,
        ),
    )
    assert merged.action == Action.REDACT
    assert merged.safe is False


def test_merge_prefers_higher_score_finding() -> None:
    weak = Finding(
        category="leakage",
        subcategory="prompt_leak_canary",
        stage="remote",
        span_start=0,
        span_end=16,
        score=0.1,
        evidence="weak",
    )
    strong = Finding(
        category="leakage",
        subcategory="prompt_leak_canary",
        stage="canary",
        span_start=0,
        span_end=16,
        score=0.99,
        evidence="strong",
        replacement="[REDACTED:canary]",
    )
    merged = merge_scan_results(
        _result(action=Action.REDACT, safe=False, findings=[weak], risk_score=0.1),
        _result(
            action=Action.REDACT,
            safe=False,
            findings=[strong],
            risk_score=0.99,
            redacted_text="clean",
        ),
    )
    assert len(merged.findings) == 1
    assert merged.findings[0].score == 0.99
    assert merged.findings[0].replacement == "[REDACTED:canary]"
    assert merged.redacted_text == "clean"
    assert merged.safe is False


def test_merge_action_rank_matches_overlay() -> None:
    """REDACT is stricter than REVIEW (aligned with Guard overlay severity)."""
    merged = merge_scan_results(
        _result(action=Action.REVIEW, safe=False, risk_score=0.5),
        _result(action=Action.REDACT, safe=False, risk_score=0.9, redacted_text="x"),
    )
    assert merged.action == Action.REDACT
    assert merged.safe is False


def test_merge_redacted_last_non_none_wins() -> None:
    """Ordered pipelines: later redaction composes on the prior base."""
    merged = merge_scan_results(
        _result(action=Action.BLOCK, safe=False, redacted_text="inj-clean secret-still-here"),
        _result(action=Action.BLOCK, safe=False, redacted_text="inj-clean secret-gone"),
    )
    assert merged.redacted_text == "inj-clean secret-gone"


def test_merge_keeps_earlier_redacted_when_later_absent() -> None:
    merged = merge_scan_results(
        _result(action=Action.REDACT, safe=False, redacted_text="only-input"),
        _result(action=Action.ALLOW, safe=True, redacted_text=None),
    )
    assert merged.action == Action.REDACT
    assert merged.redacted_text == "only-input"
    assert merged.safe is False


def test_merge_empty_findings_allow() -> None:
    merged = merge_scan_results(
        _result(action=Action.ALLOW, safe=True),
        _result(action=Action.ALLOW, safe=True),
    )
    assert merged.action == Action.ALLOW
    assert merged.safe is True
    assert merged.findings == []
    assert merged.redacted_text is None


def test_merge_abstain_not_safe() -> None:
    merged = merge_scan_results(
        _result(action=Action.ALLOW, safe=True),
        _result(action=Action.ABSTAIN, safe=True, risk_score=0.4),
    )
    assert merged.action == Action.ABSTAIN
    assert merged.safe is False
