"""CLI tests for unplug-audit output and exit behavior."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from unplug.cli import audit


def _report(*, wiring_pass: bool = True) -> dict:
    return {
        "wiring_pass": wiring_pass,
        "all_passed": False,
        "checks_passed": 1,
        "checks_total": 3,
        "checks": [
            {"name": "config_load", "passed": True, "detail": "ok"},
            {
                "name": "fp_probe_suite",
                "passed": False,
                "detail": "skipped (ML inactive)",
            },
            {"name": "ml_active", "passed": False, "detail": "inactive"},
        ],
        "ml_inactive_hint": True,
    }


def test_audit_cli_text_output_marks_skips_and_notes_ml(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: dict[str, object] = {}

    def fake_run_audit(**kwargs: object) -> dict:
        seen.update(kwargs)
        return _report(wiring_pass=True)

    monkeypatch.setattr(audit, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", ["unplug-audit", "--probes", "--workspace-root", "/tmp"])

    with pytest.raises(SystemExit) as exc:
        audit.main()

    assert exc.value.code == 0
    assert seen["workspace_root"] == Path("/tmp")
    assert seen["include_probes"] is True
    out = capsys.readouterr().out
    assert "[skip] fp_probe_suite: skipped" in out
    assert "[FAIL] ml_active: inactive" in out
    assert "FP/encoding probes skipped without ML" in out
    assert "checkpoint found but ML inactive" in out


def test_audit_cli_json_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(audit, "run_audit", lambda **_: _report(wiring_pass=False))
    monkeypatch.setattr(sys, "argv", ["unplug-audit", "--json", "--require-ml"])

    with pytest.raises(SystemExit) as exc:
        audit.main()

    assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["wiring_pass"] is False
    assert payload["checks"][0]["name"] == "config_load"
