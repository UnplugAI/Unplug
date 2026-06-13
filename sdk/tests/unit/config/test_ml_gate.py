"""ML gate default and preset behavior."""

from __future__ import annotations

from unplug.config.policy import MlGateConfig
from unplug.core.policy.decision import should_invoke_ml


def test_default_gate_skips_ml_on_benign_zero_risk() -> None:
    gate = MlGateConfig()
    assert gate.always_below_high is False
    assert (
        should_invoke_ml(
            regex_risk=0.0,
            regex_flagged=False,
            gate=gate,
            block_threshold=0.8,
        )
        is False
    )


def test_recall_preset_runs_ml_below_high() -> None:
    from unplug.config.loader import _apply_ml_gate_preset

    data = _apply_ml_gate_preset({"preset": "recall"})
    gate = MlGateConfig(**{k: v for k, v in data.items() if k in MlGateConfig.model_fields})
    assert gate.always_below_high is True
    assert (
        should_invoke_ml(
            regex_risk=0.0,
            regex_flagged=False,
            gate=gate,
            block_threshold=0.8,
        )
        is True
    )
