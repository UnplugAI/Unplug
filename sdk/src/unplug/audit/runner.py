"""Unplug security audit — wiring, ML, probes, session policy."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.audit.boundary import default_boundary_probes_path, run_boundary_probe_suite
from unplug.audit.probes import (
    default_encoding_probes_path,
    default_fp_probes_path,
    run_encoding_probe_suite,
    run_fp_probe_suite,
)
from unplug.config.guard import GuardConfig
from unplug.config.loader import load
from unplug.config.tools import ToolPolicyConfig


def _check(name: str, passed: bool, detail: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "detail": detail, **extra}


def _resolve_workspace_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.environ.get("UNPLUG_WORKSPACE_ROOT")
    if env:
        return Path(env)
    # .../jakarta/sdk/src/unplug/audit/runner.py -> unplug-v1
    return Path(__file__).resolve().parents[5]


def _resolve_checkpoint(workspace: Path) -> Path | None:
    env = os.environ.get("UNPLUG_MODEL_PATH")
    if env:
        path = Path(env)
        if path.is_dir() and (path / "config.json").is_file():
            return path
    default = (
        workspace
        / "repos/unplug_exp/dist/vm-v10-750k-diagnostic-bundle/"
        "experiments/unplug-tiny-v10-350k/checkpoint-24615"
    )
    if default.is_dir() and (default / "config.json").is_file():
        return default
    return None


def run_audit(
    *,
    workspace_root: Path | None = None,
    include_probes: bool = False,
    require_ml: bool = False,
) -> dict[str, Any]:
    workspace = _resolve_workspace_root(workspace_root)
    checks: list[dict[str, Any]] = []

    ckpt = _resolve_checkpoint(workspace)
    if ckpt is not None and (ckpt / "config.json").is_file():
        if require_ml:
            os.environ["UNPLUG_ACTIVE_MODEL"] = "small"
            os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
    elif require_ml:
        checks.append(_check("ml_checkpoint", False, "checkpoint missing or invalid"))
        return {
            "workspace_root": str(workspace),
            "checks_passed": 0,
            "checks_total": 1,
            "wiring_pass": False,
            "all_passed": False,
            "checks": checks,
            "probes": {},
        }

    try:
        cfg = load()
        checks.append(_check("config_load", True, "GuardConfig loaded"))
    except Exception as exc:
        checks.append(_check("config_load", False, str(exc)))
        cfg = None

    if ckpt is not None:
        checks.append(_check("ml_checkpoint", True, str(ckpt)))
    else:
        checks.append(_check("ml_checkpoint", True, "optional — not configured"))

    guard = Guard(config=cfg) if cfg else Guard()
    checks.append(
        _check(
            "scanners_loaded",
            len(guard.scanners_loaded) >= 4,
            ",".join(guard.scanners_loaded),
        )
    )

    ml_present = "injection_ml" in guard.scanners_loaded
    ml_ok = True
    if require_ml:
        if ml_present and not guard.ml_model_loaded:
            provider = getattr(guard, "_ml_provider", None)
            if provider is not None:
                try:
                    provider.load()
                except Exception:
                    ml_ok = False
        ml_ok = guard.ml_model_loaded if ml_present else False
    checks.append(
        _check(
            "ml_wired",
            ml_ok,
            f"ml_loaded={guard.ml_model_loaded} injection_ml={ml_present}",
        )
    )

    tools = cfg.tools if cfg else ToolPolicyConfig()
    checks.append(
        _check(
            "session_taint_enabled",
            tools.session_taint_enabled,
            f"profile={tools.profile}",
        )
    )

    guard.reset_session_taint()
    guard.scan("doc", source=Source.RETRIEVED)
    review = guard.check_tool_call("shell", {"command": "echo x"})
    taint_ok = guard.context.is_session_tainted and review.action == Action.REVIEW
    checks.append(
        _check(
            "session_taint_review_gate",
            taint_ok,
            f"session_tainted={guard.context.is_session_tainted} action={review.action.value}",
        )
    )

    readonly_cfg = (cfg or GuardConfig()).model_copy(
        update={"tools": ToolPolicyConfig(profile="readonly")}
    )
    ro_guard = Guard(config=readonly_cfg)
    ro_block = ro_guard.check_tool_call("shell", {"command": "ls"})
    ro_allow = ro_guard.check_tool_call("search", {"query": "weather"})
    checks.append(
        _check(
            "profile_readonly",
            ro_block.action == Action.BLOCK and ro_allow.action == Action.ALLOW,
            f"shell={ro_block.action.value} search={ro_allow.action.value}",
        )
    )

    fp_path = default_fp_probes_path(workspace)
    enc_path = default_encoding_probes_path(workspace)
    bnd_path = default_boundary_probes_path(workspace)
    checks.append(_check("fp_probes_file", fp_path.is_file(), str(fp_path)))
    checks.append(_check("encoding_probes_file", enc_path.is_file(), str(enc_path)))
    checks.append(_check("boundary_probes_file", bnd_path.is_file(), str(bnd_path)))

    probe_summary: dict[str, Any] = {}
    probe_guard: Guard | None = None
    if require_ml:
        probe_guard = Guard(config=cfg) if cfg else Guard()
        if probe_guard.ml_model_loaded is False:
            provider = getattr(probe_guard, "_ml_provider", None)
            if provider is not None:
                try:
                    provider.load()
                except Exception:
                    probe_guard = None

    if include_probes:
        if fp_path.is_file():
            fp_suite = run_fp_probe_suite(fp_path, base_config=cfg, guard=probe_guard)
            probe_summary["fp"] = fp_suite
            checks.append(
                _check(
                    "fp_probe_suite",
                    fp_suite.get("all_passed", False),
                    f"tp={fp_suite.get('tp')} fp={fp_suite.get('fp')} fn={fp_suite.get('fn')}",
                )
            )
        if enc_path.is_file():
            enc_suite = run_encoding_probe_suite(enc_path, base_config=cfg, guard=probe_guard)
            probe_summary["encoding"] = enc_suite
            checks.append(
                _check(
                    "encoding_probe_suite",
                    enc_suite.get("encoding_probes_pass", False),
                    f"encoding_pass={enc_suite.get('encoding_probes_pass')} "
                    f"hits={enc_suite.get('encoding_stage_hits')} "
                    f"control_fp={enc_suite.get('literal_control_fp')}",
                )
            )
        if bnd_path.is_file():
            boundary = run_boundary_probe_suite(bnd_path, base_config=cfg)
            probe_summary["boundary"] = boundary
            checks.append(
                _check(
                    "boundary_probe_suite",
                    boundary.get("all_passed", False),
                    f"passed={boundary.get('passed')} failed={boundary.get('failed')}",
                )
            )

    wiring_names = {
        "config_load",
        "scanners_loaded",
        "session_taint_enabled",
        "session_taint_review_gate",
        "profile_readonly",
        "fp_probes_file",
        "encoding_probes_file",
        "boundary_probes_file",
        "ml_checkpoint",
    }
    if require_ml:
        wiring_names.add("ml_wired")
    wiring_pass = all(c["passed"] for c in checks if c["name"] in wiring_names)
    all_pass = all(c["passed"] for c in checks)

    return {
        "workspace_root": str(workspace),
        "checks_passed": sum(1 for c in checks if c["passed"]),
        "checks_total": len(checks),
        "wiring_pass": wiring_pass,
        "all_passed": all_pass,
        "checks": checks,
        "probes": probe_summary,
    }
