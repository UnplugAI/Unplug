"""Unplug security audit: wiring, ML, probes, session policy."""

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
from unplug.ml.validation import resolve_validation_checkpoint, workspace_root


def _check(name: str, passed: bool, detail: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "passed": passed, "detail": detail, **extra}


def _resolve_workspace_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    env = os.environ.get("UNPLUG_WORKSPACE_ROOT")
    if env:
        return Path(env)
    return workspace_root()


def _resolve_checkpoint(workspace: Path) -> Path | None:
    del workspace
    return resolve_validation_checkpoint(require_weights=False)


def _ensure_ml_loaded(guard: Guard) -> bool:
    ml_present = "injection_ml" in guard.scanners_loaded
    if not ml_present:
        return False
    if guard.ml_model_loaded:
        return True
    provider = getattr(guard, "_ml_provider", None)
    if provider is not None:
        try:
            provider.load()
        except Exception:
            return False
    return guard.ml_model_loaded


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
            os.environ["UNPLUG_ACTIVE_MODEL"] = "tiny"
            os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
    elif require_ml:
        checks.append(_check("ml_checkpoint", False, "checkpoint missing or invalid"))
        checks.append(_check("ml_configured", False, "cannot verify: checkpoint missing"))
        checks.append(_check("ml_active", False, "cannot verify: checkpoint missing"))
        return {
            "workspace_root": str(workspace),
            "checks_passed": 0,
            "checks_total": len(checks),
            "wiring_pass": False,
            "all_passed": False,
            "checks": checks,
            "probes": {},
            "ml_inactive_hint": False,
        }

    try:
        cfg = load()
        checks.append(_check("config_load", True, "GuardConfig loaded"))
    except Exception as exc:
        checks.append(_check("config_load", False, str(exc)))
        cfg = None

    if ckpt is not None:
        checks.append(_check("ml_checkpoint", True, f"path={ckpt}"))
    else:
        checks.append(_check("ml_checkpoint", True, "none (optional)"))

    active_model = cfg.active_model if cfg else None
    if active_model:
        checks.append(_check("ml_configured", True, f"active_model={active_model}"))
    else:
        checks.append(
            _check(
                "ml_configured",
                False,
                "not set: set active_model or UNPLUG_ACTIVE_MODEL",
            )
        )

    guard = Guard(config=cfg) if cfg else Guard()
    checks.append(
        _check(
            "scanners_loaded",
            len(guard.scanners_loaded) >= 4,
            ",".join(guard.scanners_loaded),
        )
    )

    ml_present = "injection_ml" in guard.scanners_loaded
    ml_active = _ensure_ml_loaded(guard)
    checks.append(
        _check(
            "ml_active",
            ml_active,
            f"injection_ml={ml_present} ml_loaded={guard.ml_model_loaded}",
        )
    )

    checkpoint_found = ckpt is not None
    ml_inactive_hint = checkpoint_found and not ml_active and not require_ml

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
    candidate = Guard(config=cfg) if cfg else Guard()
    if _ensure_ml_loaded(candidate):
        probe_guard = candidate

    if include_probes:
        if fp_path.is_file():
            if probe_guard is None:
                checks.append(
                    _check(
                        "fp_probe_suite",
                        True,
                        "skipped (ML inactive; pip install unplug-ai[ml], "
                        "set active_model=tiny, or use --require-ml)",
                    )
                )
            else:
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
            if probe_guard is None:
                checks.append(
                    _check(
                        "encoding_probe_suite",
                        True,
                        "skipped (ML inactive; use --probes --require-ml for full batteries)",
                    )
                )
            else:
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
    }
    if require_ml:
        wiring_names.update({"ml_checkpoint", "ml_configured", "ml_active"})
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
        "ml_inactive_hint": ml_inactive_hint,
    }
