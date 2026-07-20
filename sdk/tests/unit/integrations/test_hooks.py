"""Tests for AgentHooks security semantics."""

from __future__ import annotations

from unittest.mock import MagicMock

from unplug import Guard
from unplug.api.enums import Action
from unplug.api.types import ScanResult
from unplug.integrations.hooks import _RETRIEVED_BLOCKED_PLACEHOLDER, AgentHooks


def test_wrap_retrieved_blocks_non_allow(monkeypatch) -> None:
    guard = Guard()
    blocked = ScanResult(
        safe=False,
        action=Action.REDACT,
        risk_score=0.9,
        findings=[],
        redacted_text="[REDACTED]",
        latency_ms=1.0,
        stages_run=["injection"],
    )
    monkeypatch.setattr(guard, "wrap_for_context", lambda text, source: f"WRAPPED:{text}")
    monkeypatch.setattr(guard, "scan", lambda text, source: blocked)
    monkeypatch.setattr(guard, "notify_taint_source", MagicMock())

    hooks = AgentHooks(guard=guard)
    content, decision = hooks.wrap_retrieved_content("evil payload")

    assert decision.allowed is False
    assert content == "[REDACTED]"
    assert decision.redacted_text == "[REDACTED]"


def test_wrap_retrieved_uses_placeholder_when_no_redaction(monkeypatch) -> None:
    guard = Guard()
    blocked = ScanResult(
        safe=False,
        action=Action.REVIEW,
        risk_score=0.6,
        findings=[],
        redacted_text=None,
        latency_ms=1.0,
        stages_run=["injection"],
    )
    monkeypatch.setattr(guard, "wrap_for_context", lambda text, source: text)
    monkeypatch.setattr(guard, "scan", lambda text, source: blocked)
    monkeypatch.setattr(guard, "notify_taint_source", MagicMock())

    hooks = AgentHooks(guard=guard)
    content, decision = hooks.wrap_retrieved_content("payload")

    assert decision.allowed is False
    assert content == _RETRIEVED_BLOCKED_PLACEHOLDER


def test_scan_user_input_blocks_abstain(monkeypatch) -> None:
    guard = Guard()
    abstain = ScanResult(
        safe=False,
        action=Action.ABSTAIN,
        risk_score=0.4,
        findings=[],
        latency_ms=1.0,
        stages_run=["injection_ml"],
    )
    monkeypatch.setattr(guard, "scan", lambda text, source: abstain)

    decision = AgentHooks(guard=guard).scan_user_input("uncertain input")
    assert decision.allowed is False


def test_hook_decision_review_vs_block_flags() -> None:
    review = ScanResult(
        safe=False,
        action=Action.REVIEW,
        risk_score=0.35,
        findings=[],
        latency_ms=0.1,
        stages_run=["toolcall"],
    )
    block = ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=0.9,
        findings=[],
        latency_ms=0.1,
        stages_run=["destructive"],
    )
    from unplug.integrations.hooks import HookDecision

    rev = HookDecision(allowed=False, result=review, message="held")
    blk = HookDecision(allowed=False, result=block, message="blocked")
    allow_result = ScanResult(
        safe=True,
        action=Action.ALLOW,
        risk_score=0.0,
        findings=[],
        latency_ms=0.0,
        stages_run=[],
    )
    ok = HookDecision(allowed=True, result=allow_result)

    assert rev.needs_review is True
    assert rev.is_block is False
    assert blk.needs_review is False
    assert blk.is_block is True
    assert ok.needs_review is False
    assert ok.is_block is False
