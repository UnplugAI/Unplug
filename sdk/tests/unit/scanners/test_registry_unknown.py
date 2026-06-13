"""Unknown scanner names fail fast at registry load."""

from __future__ import annotations

import pytest

from unplug.exceptions import ConfigError
from unplug.scanners.registry import ScannerRegistry


def test_get_many_raises_on_unknown_scanner() -> None:
    reg = ScannerRegistry()
    with pytest.raises(ConfigError, match="injecton"):
        reg.get_many(["injection", "injecton"])
