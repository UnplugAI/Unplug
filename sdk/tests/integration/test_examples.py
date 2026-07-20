"""Verify all SDK examples run successfully."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from unplug.api.enums import Action
from unplug.models import ScanResult

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"

LOCAL_EXAMPLES = [
    "agent_exfil_demo.py",
    "langgraph_hooks_demo.py",
    "agno_hooks_demo.py",
    "public_api_surface_demo.py",
]

SERVER_EXAMPLES = [
    "hosted_client.py",
    "local_sidecar_client.py",
]


def _load_main(path: Path) -> int:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert hasattr(module, "main")
    return int(module.main())


def _mock_health_client() -> MagicMock:
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get.return_value = MagicMock(status_code=200)
    return client


def _mock_unplug_client() -> MagicMock:
    benign = ScanResult(safe=True, action=Action.ALLOW, risk_score=0.0, findings=[], latency_ms=1)
    attack = ScanResult(safe=False, action=Action.BLOCK, risk_score=0.95, findings=[], latency_ms=1)
    leak = ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=0.99,
        findings=[],
        redacted_text="[REDACTED]",
        latency_ms=1,
    )
    mock = MagicMock()
    mock.scan_request.side_effect = [benign, attack]
    mock.scan_output_request.return_value = leak
    return mock


@pytest.mark.parametrize("filename", LOCAL_EXAMPLES)
def test_local_example_exits_zero(filename: str) -> None:
    path = EXAMPLES / filename
    assert path.is_file(), f"missing example: {filename}"
    assert _load_main(path) == 0


@pytest.mark.parametrize("filename", SERVER_EXAMPLES)
def test_server_example_exits_one_without_server(filename: str) -> None:
    path = EXAMPLES / filename
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get.side_effect = httpx.ConnectError("refused")
    with patch("httpx.Client", return_value=client):
        assert _load_main(path) == 1


@pytest.mark.parametrize("filename", SERVER_EXAMPLES)
def test_server_example_exits_zero_with_mock_server(filename: str) -> None:
    path = EXAMPLES / filename
    with (
        patch("httpx.Client", return_value=_mock_health_client()),
        patch("unplug.guard.UnplugClient", return_value=_mock_unplug_client()),
    ):
        assert _load_main(path) == 0


def test_docker_e2e_script_exists() -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "docker_e2e.sh"
    assert script.is_file()


@pytest.mark.requires_docker
def test_docker_e2e_script() -> None:
    import subprocess

    script = Path(__file__).resolve().parents[2] / "scripts" / "docker_e2e.sh"
    result = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"docker_e2e failed:\n{result.stdout}\n{result.stderr}")
