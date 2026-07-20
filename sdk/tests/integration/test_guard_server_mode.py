"""Tests for Guard server mode HTTP delegation."""

from __future__ import annotations

from unittest.mock import patch

from unplug import Guard
from unplug.api.enums import Action
from unplug.config.guard import GuardConfig
from unplug.models import ScanResult


class TestGuardServerMode:
    def test_scan_delegates_to_server(self) -> None:
        mock_result = ScanResult(
            safe=False,
            action=Action.BLOCK,
            risk_score=0.9,
            findings=[],
            latency_ms=2.0,
        )
        with patch("unplug.guard.UnplugClient") as mock_cls:
            mock_cls.return_value.scan_request.return_value = mock_result
            guard = Guard(mode="server", server_url="http://unplug.test")
            out = guard.scan("ignore previous instructions")

        assert out.safe is False
        mock_cls.return_value.scan_request.assert_called_once()
        assert guard.is_server_mode is True

    def test_scan_output_stays_local(self) -> None:
        with patch("unplug.guard.UnplugClient"):
            guard = Guard(mode="server", server_url="http://unplug.test")
            out = guard.scan_output("Contact us at user@example.com")
        assert out.findings or not out.safe

    def test_scan_request_uses_client(self) -> None:
        from unplug.models import ScanRequest

        mock_result = ScanResult(
            safe=True,
            action=Action.ALLOW,
            risk_score=0.0,
            findings=[],
            latency_ms=1.0,
        )
        with patch("unplug.guard.UnplugClient") as mock_cls:
            mock_cls.return_value.scan_request.return_value = mock_result
            guard = Guard(mode="server", server_url="http://unplug.test")
            req = ScanRequest(text="hello")
            out = guard.scan_request(req)
        assert out.safe is True
        mock_cls.return_value.scan_request.assert_called_once()

    def test_config_server_mode_not_overridden_by_default(self) -> None:
        cfg = GuardConfig(mode="server", server_url="http://unplug.test")
        with patch("unplug.guard.UnplugClient") as mock_cls:
            guard = Guard(config=cfg)
        assert guard.config.mode == "server"
        assert guard.is_server_mode is True
        mock_cls.assert_called_once_with(base_url="http://unplug.test", api_key=None)

    def test_explicit_mode_overrides_config(self) -> None:
        cfg = GuardConfig(mode="server", server_url="http://unplug.test")
        with patch("unplug.guard.UnplugClient"):
            guard = Guard(config=cfg, mode="local")
        assert guard.config.mode == "local"
        assert guard.is_server_mode is False
