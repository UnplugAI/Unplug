"""Streaming scanner incremental suffix scans."""

from __future__ import annotations

from unittest.mock import patch

from unplug import Guard
from unplug.api.enums import Action
from unplug.api.types import ScanResult
from unplug.config.cache import CacheConfig
from unplug.config.guard import GuardConfig
from unplug.core.runtime.cache import DEFAULT_PREFIX_OVERLAP_CHARS
from unplug.streaming import StreamScanner


def test_stream_scanner_scans_suffix_with_overlap() -> None:
    guard = Guard()
    stream = StreamScanner(
        guard,
        scan_every_chars=32,
        overlap_chars=DEFAULT_PREFIX_OVERLAP_CHARS,
        document_id="doc-1",
    )
    stream._safe_prefix_len = 500
    stream._last_result = ScanResult(
        safe=True,
        action=Action.ALLOW,
        risk_score=0.0,
        findings=[],
        latency_ms=0.0,
    )
    stream._buffer = ["x" * 600]
    stream._buffer_len = 600

    with patch.object(guard, "scan_request", wraps=guard.scan_request) as mock_scan:
        stream._scan_accumulated()
        assert mock_scan.call_count == 1
        request = mock_scan.call_args[0][0]
        assert len(request.text) == 600 - (500 - DEFAULT_PREFIX_OVERLAP_CHARS)


def test_stream_scanner_honors_explicit_overlap() -> None:
    """Explicit non-negative overlap values are honored, not silently replaced."""
    guard = Guard()
    stream = StreamScanner(guard, scan_every_chars=64, overlap_chars=0, document_id="stream-zero")
    assert stream._overlap == 0

    stream_low = StreamScanner(
        guard, scan_every_chars=64, overlap_chars=32, document_id="stream-low"
    )
    assert stream_low._overlap == 32

    stream_default = StreamScanner(guard, scan_every_chars=64, document_id="stream-default")
    assert stream_default._overlap == DEFAULT_PREFIX_OVERLAP_CHARS


def test_cache_config_accepts_low_overlap_values() -> None:
    """Positive overlap values below the default are accepted."""
    cfg = CacheConfig(prefix_overlap_chars=1)
    assert cfg.prefix_overlap_chars == 1

    cfg64 = CacheConfig(prefix_overlap_chars=64)
    assert cfg64.prefix_overlap_chars == 64

    cfg_default = CacheConfig()
    assert cfg_default.prefix_overlap_chars == DEFAULT_PREFIX_OVERLAP_CHARS


def test_guard_stream_scanner_passes_config_overlap() -> None:
    """Guard.stream_scanner() passes CacheConfig.prefix_overlap_chars to StreamScanner."""
    guard = Guard(config=GuardConfig(cache=CacheConfig(prefix_overlap_chars=64)))
    stream = guard.stream_scanner(document_id="doc")
    assert stream._overlap == 64
