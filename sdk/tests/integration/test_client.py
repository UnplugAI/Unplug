"""Tests for client.py: UnplugClient HTTP client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from unplug.client import UnplugClient
from unplug.models import ScanRequest, ScanResult


@pytest.fixture
def mock_response() -> dict:
    return {
        "safe": True,
        "action": "allow",
        "risk_score": 0.0,
        "findings": [],
        "redacted_text": None,
        "latency_ms": 1.5,
        "stages_run": [],
    }


class TestUnplugClient:
    def test_context_manager(self):
        with patch.object(httpx.Client, "close") as mock_close:
            with UnplugClient() as client:
                assert client is not None
            mock_close.assert_called_once()

    def test_scan(self, mock_response: dict):
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_response
        mock_resp.raise_for_status = MagicMock()

        with patch.object(httpx.Client, "post", return_value=mock_resp) as mock_post:
            client = UnplugClient(base_url="http://test:8000")
            result = client.scan("hello world")

        assert isinstance(result, ScanResult)
        assert result.safe is True
        mock_post.assert_called_once()

    def test_scan_with_api_key(self):
        with patch.object(httpx, "Client") as mock_client_cls:
            UnplugClient(base_url="http://test:8000", api_key="sk-test-123")
            call_kwargs = mock_client_cls.call_args[1]
            assert call_kwargs["headers"]["Authorization"] == "Bearer sk-test-123"

    def test_health(self):
        health_data = {"status": "ok", "version": "0.2.0"}
        mock_resp = MagicMock()
        mock_resp.json.return_value = health_data
        mock_resp.raise_for_status = MagicMock()

        with patch.object(httpx.Client, "get", return_value=mock_resp):
            client = UnplugClient()
            result = client.health()

        assert result["status"] == "ok"

    def test_batch_scan(self, mock_response: dict):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"results": [mock_response, mock_response]}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            client = UnplugClient()
            items = [ScanRequest(text="a"), ScanRequest(text="b")]
            results = client.batch_scan(items)

        assert len(results) == 2
        assert all(isinstance(r, ScanResult) for r in results)

    def test_close(self):
        with patch.object(httpx.Client, "close") as mock_close:
            client = UnplugClient()
            client.close()
            mock_close.assert_called_once()

    def test_http_error_raises_server_error(self):
        from unplug.exceptions import ServerError

        with patch.object(
            httpx.Client,
            "post",
            side_effect=httpx.HTTPStatusError(
                "500",
                request=httpx.Request("POST", "http://test/v1/scan"),
                response=httpx.Response(500),
            ),
        ):
            client = UnplugClient(base_url="http://test:8000")
            with pytest.raises(ServerError, match="Unplug server request failed"):
                client.scan("hello")

    def test_invalid_scan_response_raises_server_error(self):
        from unplug.exceptions import ServerError

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"not": "a scan result"}
        mock_resp.raise_for_status = MagicMock()

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            client = UnplugClient(base_url="http://localhost:8000")
            with pytest.raises(ServerError, match="invalid scan response"):
                client.scan("hello")

    def test_malformed_json_raises_server_error(self):
        import json

        from unplug.exceptions import ServerError

        mock_resp = MagicMock()
        mock_resp.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)
        mock_resp.raise_for_status = MagicMock()

        with patch.object(httpx.Client, "post", return_value=mock_resp):
            client = UnplugClient(base_url="http://localhost:8000")
            with pytest.raises(ServerError, match="malformed JSON"):
                client.scan("hello")
