"""Tests for ABSTAIN safe semantics."""

from __future__ import annotations

from unplug.api.enums import Action
from unplug.api.types import Finding
from unplug.config.policy import ScanPolicy
from unplug.core.policy import decide_action, is_result_safe


def test_abstain_not_safe_by_default() -> None:
    policy = ScanPolicy()
    findings = [
        Finding(
            category="injection_ml",
            subcategory="ml_abstain_band",
            stage="model",
            span_start=0,
            span_end=10,
            score=0.4,
            evidence="uncertain",
        )
    ]
    action = decide_action(findings, text_len=100, policy=policy, risk_score=0.4)
    assert action == Action.ABSTAIN
    assert is_result_safe(action, policy) is False


def test_abstain_safe_when_opt_in() -> None:
    policy = ScanPolicy(abstain_is_safe=True)
    assert is_result_safe(Action.ABSTAIN, policy) is True


def test_allow_always_safe() -> None:
    policy = ScanPolicy()
    assert is_result_safe(Action.ALLOW, policy) is True
