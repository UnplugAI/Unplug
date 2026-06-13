"""HTTP client for Unplug server mode."""

from __future__ import annotations

import json
import os
import warnings
from typing import Self
from urllib.parse import urlparse

import httpx
from pydantic import ValidationError

from unplug.api.enums import Source
from unplug.api.types import BatchScanRequest, ScanRequest, ScanResult
from unplug.exceptions import ServerError


def _warn_insecure_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "http":
        return
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return
    warnings.warn(
        f"Unplug server URL uses insecure http:// ({url}); use https:// in production",
        stacklevel=3,
    )


class UnplugClient:
    """Client for the Unplug server API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
    ) -> None:
        resolved_url = base_url or os.environ.get("UNPLUG_SERVER_URL", "http://localhost:8000")
        _warn_insecure_url(resolved_url)
        resolved_key = api_key or os.environ.get("UNPLUG_API_KEY")
        headers: dict[str, str] = {}
        if resolved_key:
            headers["Authorization"] = f"Bearer {resolved_key}"
        self._client = httpx.Client(
            base_url=resolved_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )

    def _post_json(self, path: str, payload: dict) -> dict:
        try:
            response = self._client.post(path, json=payload)
            response.raise_for_status()
            try:
                return response.json()
            except json.JSONDecodeError as exc:
                msg = f"Unplug server returned malformed JSON: {exc}"
                raise ServerError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"Unplug server request failed: {type(exc).__name__}: {exc}"
            raise ServerError(msg) from exc

    def _parse_scan_result(self, data: object) -> ScanResult:
        try:
            return ScanResult.model_validate(data)
        except ValidationError as exc:
            msg = f"Unplug server returned invalid scan response: {exc}"
            raise ServerError(msg) from exc

    def _get_json(self, path: str) -> dict:
        try:
            response = self._client.get(path)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            msg = f"Unplug server request failed: {type(exc).__name__}: {exc}"
            raise ServerError(msg) from exc

    def scan(
        self,
        text: str,
        source: Source | str = Source.USER,
        *,
        scanners: list[str] | None = None,
        redact: bool = True,
    ) -> ScanResult:
        request = ScanRequest(text=text, source=source, scanners=scanners, redact=redact)
        return self.scan_request(request)

    def scan_request(self, request: ScanRequest) -> ScanResult:
        data = self._post_json("/v1/scan", request.model_dump(mode="json"))
        return self._parse_scan_result(data)

    def scan_output(
        self,
        text: str,
        *,
        scanners: list[str] | None = None,
        redact: bool = True,
    ) -> ScanResult:
        request = ScanRequest(
            text=text,
            source=Source.TOOL_OUTPUT,
            scanners=scanners,
            redact=redact,
        )
        return self.scan_output_request(request)

    def scan_output_request(self, request: ScanRequest) -> ScanResult:
        data = self._post_json("/v1/scan/output", request.model_dump(mode="json"))
        return self._parse_scan_result(data)

    def batch_scan(self, items: list[ScanRequest]) -> list[ScanResult]:
        request = BatchScanRequest(items=items)
        data = self._post_json("/v1/batch", request.model_dump(mode="json"))
        return [self._parse_scan_result(r) for r in data["results"]]

    def health(self) -> dict[str, object]:
        return self._get_json("/v1/health")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
