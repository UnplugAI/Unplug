"""strict_scanner_allowlist raises when mandatory scanners omitted."""

from __future__ import annotations

import pytest

from unplug import Guard
from unplug.config.guard import GuardConfig, resolve_input_scanners
from unplug.exceptions import ConfigError
from unplug.models import ScanRequest


def test_strict_raises_on_omitted_mandatory() -> None:
    with pytest.raises(ConfigError, match="injection"):
        resolve_input_scanners(["harmful"], strict=True)


def test_non_strict_unions_mandatory() -> None:
    merged = resolve_input_scanners(["harmful"], strict=False)
    assert merged is not None
    assert "injection" in merged
    assert "destructive" in merged


def test_guard_strict_allowlist_propagates_config_error() -> None:
    guard = Guard(config=GuardConfig(strict_scanner_allowlist=True))
    with pytest.raises(ConfigError, match="injection"):
        guard.scan_request(ScanRequest(text="hello", scanners=["harmful"]))


def test_empty_scanner_list_uses_default_set() -> None:
    guard = Guard(config=GuardConfig(scanners=["injection", "destructive", "harmful"]))
    result = guard.scan_request(ScanRequest(text="hello world", scanners=[]))
    assert result.safe is True
