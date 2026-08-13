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


def test_preset_expands_when_constructed_in_python() -> None:
    """A preset set in Python must behave the same as one set in unplug.toml."""
    for preset, always_below_high, gray_low in (
        ("recall", True, 0.0),
        ("balanced", False, 0.3),
        ("latency", False, 0.5),
    ):
        gate = MlGateConfig(preset=preset)  # type: ignore[arg-type]
        assert gate.always_below_high is always_below_high, preset
        assert gate.gray_low == gray_low, preset


def test_python_and_toml_presets_agree() -> None:
    from unplug.config.loader import _apply_ml_gate_preset

    for preset in ("recall", "balanced", "latency"):
        via_loader = _apply_ml_gate_preset({"preset": preset})
        assert (
            MlGateConfig(preset=preset).model_dump()
            == MlGateConfig(  # type: ignore[arg-type]
                **{k: v for k, v in via_loader.items() if k in MlGateConfig.model_fields}
            ).model_dump()
        ), preset
