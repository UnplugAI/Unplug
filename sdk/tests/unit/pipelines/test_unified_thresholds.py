"""Input and output pipelines share ScanPolicy threshold decisions."""

from __future__ import annotations

from unplug.config.policy import ScanPolicy
from unplug.core.config import PipelineConfig
from unplug.models import Action, Finding
from unplug.pipelines.input import InputPipeline
from unplug.pipelines.output import OutputPipeline


def _finding(score: float) -> Finding:
    return Finding(
        category="leakage",
        subcategory="test",
        stage="regex",
        span_start=0,
        span_end=1,
        score=score,
        evidence="test",
    )


def test_same_score_same_action_input_and_output() -> None:
    policy = ScanPolicy(block_threshold=0.8, redact_threshold=0.5, review_threshold=0.3)
    config = PipelineConfig(policy=policy)
    inp = InputPipeline(scanners=[], config=config)
    out = OutputPipeline(config=config)
    text_len = 100
    for score, expected in (
        (0.1, Action.ALLOW),
        (0.35, Action.REVIEW),
        (0.55, Action.REDACT),
        (0.85, Action.BLOCK),
    ):
        findings = [_finding(score)]
        inp_action = inp._decide(score, findings, text_len=text_len, policy=policy)
        out_action = out._decide(score, findings, text_len=text_len, policy=policy)
        assert inp_action == out_action == expected
