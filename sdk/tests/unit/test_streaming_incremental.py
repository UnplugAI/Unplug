"""Streaming scanner incremental suffix scans."""

from __future__ import annotations

from unittest.mock import patch

from unplug import Guard
from unplug.api.types import ScanResult
from unplug.models import Action
from unplug.streaming import StreamScanner


def test_stream_scanner_scans_suffix_with_overlap() -> None:
    guard = Guard()
    stream = StreamScanner(guard, scan_every_chars=32, overlap_chars=8, document_id="doc-1")
    stream._safe_prefix_len = 40
    stream._last_result = ScanResult(
        safe=True,
        action=Action.ALLOW,
        risk_score=0.0,
        findings=[],
        latency_ms=0.0,
    )
    stream._buffer = ["x" * 50]
    stream._buffer_len = 50

    with patch.object(guard, "scan_request", wraps=guard.scan_request) as mock_scan:
        stream._scan_accumulated()
        assert mock_scan.call_count == 1
        request = mock_scan.call_args[0][0]
        assert len(request.text) < 50
