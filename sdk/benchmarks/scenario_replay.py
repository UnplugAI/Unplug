"""YAML scenario replay: multi-step agent attack sequences for regression testing."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from unplug import Guard
from unplug.models import ScanResult


@dataclass
class StepExpectation:
    safe: bool | None = None
    min_risk: float | None = None
    categories: list[str] = field(default_factory=list)
    subcategories: list[str] = field(default_factory=list)
    action: str | None = None


@dataclass
class ScenarioStep:
    action: str
    text: str = ""
    source: str = "user"
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    agent_id: str | None = None
    delay_s: float = 0.0
    expect: StepExpectation = field(default_factory=StepExpectation)


@dataclass
class Scenario:
    name: str
    description: str = ""
    session_id: str = "scenario-session"
    steps: list[ScenarioStep] = field(default_factory=list)


@dataclass
class StepResult:
    step_index: int
    action: str
    passed: bool
    scan_result: ScanResult | None = None
    errors: list[str] = field(default_factory=list)


@dataclass
class ReplayResult:
    scenario: str
    passed: bool
    steps_run: int
    steps_passed: int
    step_results: list[StepResult] = field(default_factory=list)
    total_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "steps_run": self.steps_run,
            "steps_passed": self.steps_passed,
            "total_time_ms": round(self.total_time_ms, 1),
            "steps": [
                {
                    "index": sr.step_index,
                    "action": sr.action,
                    "passed": sr.passed,
                    "errors": sr.errors,
                    "risk_score": sr.scan_result.risk_score if sr.scan_result else None,
                    "action_taken": (sr.scan_result.action.value if sr.scan_result else None),
                }
                for sr in self.step_results
            ],
        }


def load_scenario(path: Path) -> Scenario:
    """Load a YAML scenario file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        msg = f"Invalid scenario format: {path}"
        raise ValueError(msg)

    steps: list[ScenarioStep] = []
    for raw in data.get("steps", []):
        expect_raw = raw.get("expect", {}) or {}
        expect = StepExpectation(
            safe=expect_raw.get("safe"),
            min_risk=expect_raw.get("min_risk"),
            categories=list(expect_raw.get("categories", [])),
            subcategories=list(expect_raw.get("subcategories", [])),
            action=expect_raw.get("action"),
        )
        steps.append(
            ScenarioStep(
                action=str(raw["action"]),
                text=str(raw.get("text", "")),
                source=str(raw.get("source", "user")),
                tool_name=str(raw.get("tool_name", "")),
                arguments=dict(raw.get("arguments", {})),
                agent_id=raw.get("agent_id"),
                delay_s=float(raw.get("delay_s", raw.get("delay", 0))),
                expect=expect,
            )
        )

    return Scenario(
        name=str(data.get("name", path.stem)),
        description=str(data.get("description", "")),
        session_id=str(data.get("session_id", "scenario-session")),
        steps=steps,
    )


def _run_step(guard: Guard, step: ScenarioStep) -> ScanResult:
    if step.agent_id:
        guard.context.agent_id = step.agent_id
    if step.action == "scan":
        return guard.scan(step.text, source=step.source)
    if step.action == "scan_output":
        return guard.scan_output(step.text)
    if step.action == "tool_call":
        return guard.check_tool_call(step.tool_name, step.arguments)
    msg = f"Unknown scenario action: {step.action!r}"
    raise ValueError(msg)


def _check_expectation(result: ScanResult, expect: StepExpectation) -> list[str]:
    errors: list[str] = []
    if expect.safe is not None:
        actual_safe = result.safe
        if actual_safe != expect.safe:
            errors.append(f"expected safe={expect.safe}, got safe={actual_safe}")
    if expect.min_risk is not None and result.risk_score < expect.min_risk:
        errors.append(f"expected risk>={expect.min_risk}, got {result.risk_score:.3f}")
    if expect.action is not None and result.action.value != expect.action:
        errors.append(f"expected action={expect.action}, got {result.action.value}")
    if expect.categories:
        found = {f.category for f in result.findings}
        missing = [c for c in expect.categories if c not in found]
        if missing:
            errors.append(f"missing finding categories: {missing} (found {sorted(found)})")
    if expect.subcategories:
        found = {f.subcategory for f in result.findings}
        missing = [s for s in expect.subcategories if s not in found]
        if missing:
            errors.append(f"missing subcategories: {missing} (found {sorted(found)})")
    return errors


def replay_scenario(
    scenario: Scenario,
    guard: Guard | None = None,
) -> ReplayResult:
    """Replay scenario steps through a single Guard session (state carries forward)."""
    active = guard or Guard()
    active.context.session_id = scenario.session_id
    start = time.perf_counter()
    step_results: list[StepResult] = []
    passed_count = 0

    for idx, step in enumerate(scenario.steps):
        if step.delay_s > 0:
            time.sleep(step.delay_s)
        try:
            scan_result = _run_step(active, step)
            errors = _check_expectation(scan_result, step.expect)
        except Exception as exc:
            scan_result = None
            errors = [f"{type(exc).__name__}: {exc}"]

        ok = not errors
        if ok:
            passed_count += 1
        step_results.append(
            StepResult(
                step_index=idx,
                action=step.action,
                passed=ok,
                scan_result=scan_result,
                errors=errors,
            )
        )

    total_ms = (time.perf_counter() - start) * 1000
    all_passed = passed_count == len(scenario.steps)
    return ReplayResult(
        scenario=scenario.name,
        passed=all_passed,
        steps_run=len(scenario.steps),
        steps_passed=passed_count,
        step_results=step_results,
        total_time_ms=total_ms,
    )


def print_replay_report(result: ReplayResult) -> None:
    """Print human-readable scenario replay report."""
    status = "PASS" if result.passed else "FAIL"
    print("\n" + "=" * 72)
    print(f"SCENARIO REPLAY: {result.scenario} [{status}]")
    print("=" * 72)
    print(f"Steps: {result.steps_passed}/{result.steps_run} passed ({result.total_time_ms:.0f}ms)")
    for sr in result.step_results:
        mark = "ok" if sr.passed else "FAIL"
        risk = f"{sr.scan_result.risk_score:.2f}" if sr.scan_result else "n/a"
        print(f"  [{mark}] step {sr.step_index}: {sr.action} risk={risk}")
        for err in sr.errors:
            print(f"         {err}")
    print("=" * 72)
