"""Tests for ML abstain band decision logic."""

from __future__ import annotations

from unplug.api.enums import Action
from unplug.config.policy import ScanPolicy
from unplug.core.ml_band import MlBand, decide_ml_band
from unplug.core.policy import decide_action
from unplug.models import Finding

_KW = {"tau_doc": 0.9, "tau_span": 0.45, "tau_abstain_low": 0.35}


class TestDecideMlBand:
    def test_block_on_high_doc(self) -> None:
        band = decide_ml_band(doc_score=0.95, span_score=0.1, **_KW)
        assert band == MlBand.BLOCK

    def test_block_on_high_span(self) -> None:
        band = decide_ml_band(doc_score=0.2, span_score=0.8, **_KW)
        assert band == MlBand.BLOCK

    def test_allow_on_low_scores(self) -> None:
        band = decide_ml_band(doc_score=0.1, span_score=0.1, **_KW)
        assert band == MlBand.ALLOW

    def test_abstain_in_middle_band(self) -> None:
        band = decide_ml_band(doc_score=0.5, span_score=0.2, **_KW)
        assert band == MlBand.ABSTAIN


class TestAbstainPolicy:
    def test_abstain_action_from_ml_band_finding(self) -> None:
        findings = [
            Finding(
                category="injection",
                subcategory="ml_abstain_band",
                stage="ml_band",
                span_start=0,
                span_end=0,
                score=0.6,
                evidence="uncertain",
            )
        ]
        action = decide_action(findings, text_len=100, policy=ScanPolicy(), risk_score=0.6)
        assert action == Action.ABSTAIN

    def test_abstain_finding_blocks_via_coverage_gate(self) -> None:
        findings = [
            Finding(
                category="injection",
                subcategory="ml_abstain_band",
                stage="ml_band",
                span_start=0,
                span_end=100,
                score=0.85,
                evidence="uncertain but full-document coverage",
            )
        ]
        action = decide_action(findings, text_len=100, policy=ScanPolicy(), risk_score=0.85)
        assert action == Action.BLOCK

    def test_high_risk_abstain_finding_blocks(self) -> None:
        findings = [
            Finding(
                category="injection",
                subcategory="ml_abstain_band",
                stage="ml_band",
                span_start=2,
                span_end=5,
                score=0.85,
                evidence="uncertain but high doc score",
            )
        ]
        action = decide_action(findings, text_len=100, policy=ScanPolicy(), risk_score=0.85)
        assert action == Action.BLOCK

    def test_abstain_disabled_falls_through(self) -> None:
        findings = [
            Finding(
                category="injection",
                subcategory="ml_abstain_band",
                stage="ml_band",
                span_start=2,
                span_end=5,
                score=0.6,
                evidence="uncertain",
            )
        ]
        policy = ScanPolicy(abstain_enabled=False)
        action = decide_action(findings, text_len=100, policy=policy, risk_score=0.6)
        assert action == Action.REDACT
