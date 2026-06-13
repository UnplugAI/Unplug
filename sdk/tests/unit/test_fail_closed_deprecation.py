"""fail_closed deprecation still blocks on guard errors."""

from __future__ import annotations

import warnings
from unittest.mock import patch

from unplug import Guard
from unplug.config.guard import GuardConfig
from unplug.config.loader import build_config
from unplug.models import Action


def test_fail_closed_false_warns_on_init() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Guard(config=build_config({"guard": {"fail_closed": False}}))
    assert any(
        issubclass(w.category, DeprecationWarning) and "fail_closed" in str(w.message)
        for w in caught
    )


def test_guard_error_still_blocks() -> None:
    guard = Guard()
    with patch.object(guard._input_pipeline, "run", side_effect=RuntimeError("boom")):
        result = guard.scan("hello")
    assert result.action == Action.BLOCK
    assert not result.safe


def test_fail_mode_open_warns() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Guard(fail_mode="open", config=GuardConfig())
    assert any(
        issubclass(w.category, DeprecationWarning) and "fail_mode" in str(w.message) for w in caught
    )
