"""Guard warns exactly once, with the documented text, when ML is configured but absent.

This message is the only thing an operator sees when they asked for a model and got
regex-only scanning instead. It names the pip extra and the download command, so the
wording is load-bearing: someone reads it and runs what it says.

`_warn_ml_degraded` merged two previously separate warning blocks (#104, PR #124), so
these pin both branches against a future refactor changing the text by accident.

Both tests force the outcome by patching the model-spec call, so they behave the same
whether or not the `ml` extra is installed and never touch the network.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from unplug.config.guard import GuardConfig
from unplug.guard import Guard

FIX_HINT = (
    'Fix: pip install "unplug-ai[ml]", then unplug-models download tiny '
    "(or set UNPLUG_MODEL_PATH). Continuing with regex scanners only."
)


def _degraded_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if "injection_ml" in r.getMessage()]


class TestMlDegradedWarning:
    def test_load_failure_names_the_exception_type(self, caplog: pytest.LogCaptureFixture) -> None:
        """A caught load error is reported with its exception class name."""
        with (
            patch(
                "unplug.guard.prepare_active_model_spec",
                side_effect=RuntimeError("boom"),
            ),
            caplog.at_level(logging.WARNING, logger="unplug"),
        ):
            guard = Guard(config=GuardConfig(active_model="tiny"))

        records = _degraded_records(caplog)
        assert len(records) == 1, "the two call sites must be mutually exclusive"
        assert records[0].levelno == logging.WARNING
        assert records[0].getMessage() == (
            "active_model=tiny configured but injection_ml failed to load (RuntimeError). "
            + FIX_HINT
        )
        assert guard._ml_degraded is True

    def test_model_never_wired_reports_not_loaded(self, caplog: pytest.LogCaptureFixture) -> None:
        """No exception, no provider: the message says 'is not loaded', with no class name."""
        with (
            patch("unplug.guard.prepare_active_model_spec", return_value=None),
            caplog.at_level(logging.WARNING, logger="unplug"),
        ):
            guard = Guard(config=GuardConfig(active_model="tiny"))

        records = _degraded_records(caplog)
        assert len(records) == 1
        assert records[0].getMessage() == (
            "active_model=tiny configured but injection_ml is not loaded. " + FIX_HINT
        )
        assert guard._ml_degraded is True

    def test_no_active_model_does_not_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        """Regex-only is the default, not a degraded state, so it must stay quiet."""
        with caplog.at_level(logging.WARNING, logger="unplug"):
            guard = Guard(config=GuardConfig())

        assert _degraded_records(caplog) == []
        assert guard._ml_degraded is False
