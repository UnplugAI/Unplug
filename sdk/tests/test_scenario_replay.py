"""Tests for YAML scenario replay."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.scenario_replay import load_scenario, replay_scenario

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "scenarios"


@pytest.mark.parametrize(
    "filename",
    ["injection_smoke.yaml", "exfil_kill_chain.yaml", "agent_collusion.yaml"],
)
def test_builtin_scenarios_pass(filename: str) -> None:
    path = SCENARIOS_DIR / filename
    scenario = load_scenario(path)
    result = replay_scenario(scenario)
    assert result.passed, result.step_results


def test_load_scenario_fields() -> None:
    scenario = load_scenario(SCENARIOS_DIR / "injection_smoke.yaml")
    assert scenario.name == "Injection Detection"
    assert len(scenario.steps) == 3
    assert scenario.steps[1].expect.safe is False
