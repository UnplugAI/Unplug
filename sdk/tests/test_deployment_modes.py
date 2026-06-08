"""Tests for hosted vs embedded vs sidecar deployment contracts."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from unplug import Guard
from unplug.cli.sidecar import _cmd_doctor, _cmd_env
from unplug.ml.validation import load_ml_validation_manifest, manifest_path


class TestDeploymentManifest:
    def test_deployment_doc_exists(self) -> None:
        doc = manifest_path().parents[1] / "docs" / "DEPLOYMENT.md"
        assert doc.is_file()
        body = doc.read_text(encoding="utf-8")
        assert "Hosted" in body
        assert "Local embedded" in body
        assert "Local sidecar" in body

    def test_manifest_tier_is_tiny(self) -> None:
        assert load_ml_validation_manifest()["tier"] == "tiny"


class TestGuardModes:
    def test_local_mode_no_server_client(self) -> None:
        guard = Guard(mode="local")
        assert guard.is_server_mode is False

    def test_server_mode_uses_client(self) -> None:
        with patch("unplug.guard.UnplugClient") as mock_cls:
            guard = Guard(mode="server", server_url="http://127.0.0.1:8000")
        assert guard.is_server_mode is True
        mock_cls.assert_called_once()
        call_kw = mock_cls.call_args.kwargs
        assert call_kw["base_url"] == "http://127.0.0.1:8000"

    def test_sidecar_url_from_env(self) -> None:
        with (
            patch.dict(os.environ, {"UNPLUG_SERVER_URL": "http://127.0.0.1:8765"}),
            patch("unplug.guard.UnplugClient") as mock_cls,
        ):
            Guard(mode="server")
        assert mock_cls.call_args.kwargs["base_url"] == "http://127.0.0.1:8765"


class TestSidecarCli:
    def test_env_bash_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = MagicMock(url="http://127.0.0.1:8000", shell="bash")
        assert _cmd_env(args) == 0
        out = capsys.readouterr().out
        assert 'UNPLUG_SERVER_URL="http://127.0.0.1:8000"' in out

    def test_env_fish_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = MagicMock(url="http://127.0.0.1:8000", shell="fish")
        assert _cmd_env(args) == 0
        out = capsys.readouterr().out
        assert "set -gx UNPLUG_SERVER_URL" in out

    def test_doctor_unreachable(self) -> None:
        import httpx

        args = MagicMock(url="http://127.0.0.1:1", timeout=0.5, format="text")
        client = MagicMock()
        client.__enter__ = MagicMock(return_value=client)
        client.__exit__ = MagicMock(return_value=False)
        client.get.side_effect = httpx.ConnectError("refused")
        with patch("unplug.cli.sidecar.httpx.Client", return_value=client):
            assert _cmd_doctor(args) == 1

    def test_doctor_json_format(self, capsys: pytest.CaptureFixture[str]) -> None:
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

        args = MagicMock(url="http://127.0.0.1:8000", timeout=1.0, format="json")
        with patch("unplug.cli.sidecar.httpx.Client", return_value=client):
            assert _cmd_doctor(args) == 0
        assert '"status": "ok"' in capsys.readouterr().out


class TestLocalSidecarExample:
    def test_example_imports(self) -> None:
        example = manifest_path().parents[1] / "examples" / "local_sidecar_client.py"
        assert example.is_file()
        code = example.read_text(encoding="utf-8")
        assert 'mode="server"' in code
        assert "check_tool_call" in code
