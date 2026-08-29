"""Tests for audit runner and boundary probes."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from unplug.audit.boundary import default_boundary_probes_path, run_boundary_probe_suite
from unplug.audit.runner import run_audit
from unplug.ml.validation import resolve_validation_checkpoint

# These modules gate on resolve_validation_checkpoint(), which reads the machine
# model cache at import time via skipif. They opt out of the empty-cache isolation
# fixture so the skip decision and the test body see the same cache (#163).
pytestmark = pytest.mark.real_model_cache

WORKSPACE = Path(__file__).resolve().parents[4]


def _checkpoint() -> Path | None:
    return resolve_validation_checkpoint(require_weights=False)


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


def test_run_audit_ml_checks_split() -> None:
    report = run_audit(workspace_root=WORKSPACE, include_probes=False)
    names = {c["name"] for c in report["checks"]}
    assert {"ml_checkpoint", "ml_configured", "ml_active"}.issubset(names)


@pytest.mark.skipif(_checkpoint() is None, reason="checkpoint not available")
def test_run_audit_path_only_wires_ml() -> None:
    pytest.importorskip("torch")
    prev_model = os.environ.get("UNPLUG_ACTIVE_MODEL")
    prev_path = os.environ.get("UNPLUG_MODEL_PATH")
    try:
        os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
        os.environ["UNPLUG_MODEL_PATH"] = str(_checkpoint())
        report = run_audit(workspace_root=WORKSPACE, include_probes=False)
        ml_configured = next(c for c in report["checks"] if c["name"] == "ml_configured")
        ml_active = next(c for c in report["checks"] if c["name"] == "ml_active")
        assert ml_configured["passed"] is True
        assert "active_model=tiny" in ml_configured["detail"]
        assert ml_active["passed"] is True
        assert "injection_ml=True" in ml_active["detail"]
    finally:
        if prev_model is None:
            os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
        else:
            os.environ["UNPLUG_ACTIVE_MODEL"] = prev_model
        if prev_path is None:
            os.environ.pop("UNPLUG_MODEL_PATH", None)
        else:
            os.environ["UNPLUG_MODEL_PATH"] = prev_path


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


def test_run_audit_ml_probes_skipped_mark_not_passed() -> None:
    """When --probes runs without ML, skipped FP/encoding must not count as passed."""
    report = run_audit(workspace_root=WORKSPACE, include_probes=True)
    fp = next(c for c in report["checks"] if c["name"] == "fp_probe_suite")
    enc = next(c for c in report["checks"] if c["name"] == "encoding_probe_suite")
    if not fp["detail"].startswith("skipped"):
        pytest.skip("ML active in this environment; skipped-probe path not exercised")
    assert fp["passed"] is False
    assert enc["passed"] is False
    assert report["all_passed"] is False
    assert report["wiring_pass"] is True


@pytest.mark.skipif(_checkpoint() is None, reason="checkpoint not available")
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
        ml_check = next(c for c in report["checks"] if c["name"] == "ml_active")
        assert ml_check["passed"] is True
        assert "injection_ml=True" in ml_check["detail"]
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


@pytest.mark.skipif(_checkpoint() is None, reason="checkpoint not available")
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
