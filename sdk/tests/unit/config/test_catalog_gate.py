"""Per-tier ml_gate tuning resolved from the model catalog."""

from __future__ import annotations

from unplug.config.guard import GuardConfig, PipelineConfig
from unplug.config.policy import MlGateConfig
from unplug.core.runtime.model_runtime import apply_catalog_gate
from unplug.ml.catalog import load_catalog


def test_tiny_declares_its_gate_in_the_catalog() -> None:
    """Gate tuning travels with the weights, not with a Guard constructor."""
    entry = load_catalog().get("tiny")
    assert entry is not None
    assert entry.gate == {"preset": "recall"}


def test_catalog_gate_applied_when_caller_left_it_default() -> None:
    cfg = apply_catalog_gate(GuardConfig(active_model="tiny"))
    assert cfg.pipeline.ml_gate.always_below_high is True
    assert cfg.pipeline.ml_gate.gray_low == 0.0


def test_explicit_gate_beats_the_catalog() -> None:
    cfg = apply_catalog_gate(
        GuardConfig(
            active_model="tiny",
            pipeline=PipelineConfig(ml_gate=MlGateConfig(preset="latency")),
        )
    )
    assert cfg.pipeline.ml_gate.always_below_high is False
    assert cfg.pipeline.ml_gate.gray_low == 0.5


def test_no_active_model_keeps_the_default_gate() -> None:
    cfg = apply_catalog_gate(GuardConfig())
    assert cfg.pipeline.ml_gate == MlGateConfig()


def test_unknown_tier_is_not_an_error_here() -> None:
    """Tier validation belongs to spec resolution; the gate step just passes through."""
    cfg = apply_catalog_gate(GuardConfig(active_model="does-not-exist"))
    assert cfg.pipeline.ml_gate == MlGateConfig()
