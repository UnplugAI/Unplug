"""Deterministic agent boundary probes: session taint, profiles, destructive gate."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from unplug import Guard
from unplug.audit.paths import resolve_probe_path
from unplug.config.guard import GuardConfig
from unplug.config.tools import ToolPolicyConfig
from unplug.models import Source


def default_boundary_probes_path(workspace_root: Path) -> Path:
    return resolve_probe_path("agent_boundary_probe_queries.json", workspace_root)


def _run_step(guard: Guard, step: dict[str, Any]) -> dict[str, Any]:
    action = step["action"]
    if action == "scan":
        source = Source(step.get("source", "user"))
        result = guard.scan(step["text"], source=source)
        return {"action": action, "result_action": result.action.value, "safe": result.safe}
    if action == "scan_output":
        result = guard.scan_output(step["text"])
        return {"action": action, "result_action": result.action.value, "safe": result.safe}
    if action == "reset_taint":
        guard.reset_session_taint()
        return {"action": action, "session_tainted": guard.context.is_session_tainted}
    if action == "tool":
        approved = step.get("approved")
        result = guard.check_tool_call(
            step["tool"],
            step.get("args", {}),
            approved=approved,
        )
        return {
            "action": action,
            "tool": step["tool"],
            "result_action": result.action.value,
            "safe": result.safe,
            "approval": result.approval.model_dump(mode="json") if result.approval else None,
        }
    msg = f"Unknown step action: {action}"
    raise ValueError(msg)


def run_boundary_probe_suite(
    probes_path: Path,
    *,
    base_config: GuardConfig | None = None,
) -> dict[str, Any]:
    if not probes_path.is_file():
        return {"error": f"boundary probes not found: {probes_path}", "results": []}

    probes = json.loads(probes_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    passed = failed = 0

    for probe in probes:
        profile = probe.get("profile")
        tools = ToolPolicyConfig(profile=profile) if profile else ToolPolicyConfig()
        cfg = (base_config or GuardConfig()).model_copy(update={"tools": tools})
        guard = Guard(config=cfg)
        step_results: list[dict[str, Any]] = []
        probe_ok = True

        for step in probe.get("steps", []):
            out = _run_step(guard, step)
            step_results.append(out)
            expected = step.get("expect_action")
            if expected and out.get("result_action") != expected:
                probe_ok = False

        if probe_ok:
            passed += 1
        else:
            failed += 1
        rows.append(
            {
                "id": probe.get("id"),
                "kind": probe.get("kind"),
                "passed": probe_ok,
                "steps": step_results,
            }
        )

    return {
        "probes_file": str(probes_path),
        "passed": passed,
        "failed": failed,
        "all_passed": failed == 0,
        "results": rows,
    }
