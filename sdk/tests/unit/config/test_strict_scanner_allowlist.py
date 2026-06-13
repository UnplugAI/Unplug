"""strict_scanner_allowlist raises when mandatory scanners omitted."""

from __future__ import annotations

import pytest

from unplug.config.guard import resolve_input_scanners
from unplug.exceptions import ConfigError


def test_strict_raises_on_omitted_mandatory() -> None:
    with pytest.raises(ConfigError, match="injection"):
        resolve_input_scanners(["harmful"], strict=True)


def test_non_strict_unions_mandatory() -> None:
    merged = resolve_input_scanners(["harmful"], strict=False)
    assert merged is not None
    assert "injection" in merged
    assert "destructive" in merged
