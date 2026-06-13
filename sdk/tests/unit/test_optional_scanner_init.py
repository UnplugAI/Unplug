"""Guard init validates optional scanner extras."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from unplug.exceptions import ConfigError
from unplug.guard import Guard


def test_pii_without_presidio_raises() -> None:
    with (
        patch(
            "unplug.optional.presidio.get_analyzer_engine_class",
            side_effect=ImportError("missing"),
        ),
        pytest.raises(ConfigError, match="presidio"),
    ):
        Guard(scanners=["injection", "pii"])
