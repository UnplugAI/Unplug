"""Tests for unplug-sidecar CLI."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from unplug.cli.sidecar import _cmd_doctor, _cmd_env


def test_env_prints_exports() -> None:
    args = MagicMock(url="http://127.0.0.1:9000", shell="bash")
    assert _cmd_env(args) == 0


def test_doctor_ok() -> None:
    live_resp = MagicMock()
    live_resp.raise_for_status = MagicMock()
    health_resp = MagicMock()
    health_resp.raise_for_status = MagicMock()
    health_resp.json.return_value = {
        "status": "ok",
        "version": "0.1.0",
        "scanners_loaded": ["injection"],
        "model_loaded": True,
    }

    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get.side_effect = [live_resp, health_resp]

    args = MagicMock(url="http://127.0.0.1:8000", timeout=1.0, format="text")
    with patch("unplug.cli.sidecar.httpx.Client", return_value=client):
        assert _cmd_doctor(args) == 0
