"""Tests for audit runner and boundary probes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from unplug.audit.boundary import default_boundary_probes_path, run_boundary_probe_suite
from unplug.audit.runner import run_audit

WORKSPACE = Path(__file__).resolve().parents[3]
DEFAULT_CKPT = (
    WORKSPACE / "repos/unplug_exp/dist/vm-v10-750k-diagnostic-bundle/"
    "experiments/unplug-tiny-v10-350k/checkpoint-24615"
)


def test_boundary_probe_suite_all_pass() -> None:
    path = default_boundary_probes_path(WORKSPACE)
    if not path.is_file():
        return
    report = run_boundary_probe_suite(path)
    assert report["all_passed"] is True
    assert report["failed"] == 0


def test_run_audit_wiring_pass() -> None:
    report = run_audit(workspace_root=WORKSPACE, include_probes=False)
    assert report["wiring_pass"] is True
    names = {c["name"] for c in report["checks"]}
    assert "session_taint_review_gate" in names
    assert "profile_readonly" in names


def test_run_audit_with_boundary_probes() -> None:
    path = default_boundary_probes_path(WORKSPACE)
    if not path.is_file():
        return
    report = run_audit(workspace_root=WORKSPACE, include_probes=True)
    probes = report.get("probes", {})
    assert "boundary" in probes
    names = {c["name"] for c in report["checks"]}
    assert "boundary_probe_suite" in names
    assert "fp_probe_suite" in names
    assert "encoding_probe_suite" in names


@pytest.mark.skipif(not DEFAULT_CKPT.is_dir(), reason="checkpoint not available")
def test_run_audit_require_ml_wires_injection() -> None:
    pytest.importorskip("torch")
    prev_model = os.environ.get("UNPLUG_ACTIVE_MODEL")
    prev_path = os.environ.get("UNPLUG_MODEL_PATH")
    try:
        report = run_audit(
            workspace_root=WORKSPACE,
            include_probes=False,
            require_ml=True,
        )
        ml_check = next(c for c in report["checks"] if c["name"] == "ml_wired")
        assert ml_check["passed"] is True
        assert "injection_ml=True" in ml_check["detail"] or "ml_loaded=True" in ml_check["detail"]
        assert report["wiring_pass"] is True
    finally:
        if prev_model is None:
            os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
        else:
            os.environ["UNPLUG_ACTIVE_MODEL"] = prev_model
        if prev_path is None:
            os.environ.pop("UNPLUG_MODEL_PATH", None)
        else:
            os.environ["UNPLUG_MODEL_PATH"] = prev_path


@pytest.mark.skipif(not DEFAULT_CKPT.is_dir(), reason="checkpoint not available")
def test_run_audit_probes_with_require_ml() -> None:
    pytest.importorskip("torch")
    prev_model = os.environ.get("UNPLUG_ACTIVE_MODEL")
    prev_path = os.environ.get("UNPLUG_MODEL_PATH")
    try:
        report = run_audit(
            workspace_root=WORKSPACE,
            include_probes=True,
            require_ml=True,
        )
        assert report["wiring_pass"] is True
        fp = report.get("probes", {}).get("fp", {})
        assert fp.get("tp", 0) >= 1
    finally:
        if prev_model is None:
            os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
        else:
            os.environ["UNPLUG_ACTIVE_MODEL"] = prev_model
        if prev_path is None:
            os.environ.pop("UNPLUG_MODEL_PATH", None)
        else:
            os.environ["UNPLUG_MODEL_PATH"] = prev_path
