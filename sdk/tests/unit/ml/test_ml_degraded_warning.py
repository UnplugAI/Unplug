"""The degraded-ML warning is written in one place but still names its cause."""

from __future__ import annotations

import logging

import pytest

from unplug.config.guard import GuardConfig
from unplug.guard import Guard

_FIX_HINT = (
    'Fix: pip install "unplug-ai[ml]", then unplug-models download tiny '
    "(or set UNPLUG_MODEL_PATH). Continuing with regex scanners only."
)


@pytest.fixture
def tiny_config() -> GuardConfig:
    return GuardConfig(active_model="tiny", scanners=["injection"])


def test_load_failure_names_the_exception(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tiny_config: GuardConfig,
) -> None:
    def boom(_cfg: GuardConfig) -> None:
        raise RuntimeError("no weights here")

    monkeypatch.setattr("unplug.guard.prepare_active_model_spec", boom)

    with caplog.at_level(logging.WARNING, logger="unplug.guard"):
        guard = Guard(config=tiny_config)

    assert guard.ml_degraded is True
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == [
        f"active_model=tiny configured but injection_ml failed to load (RuntimeError). {_FIX_HINT}"
    ]


def test_missing_model_says_not_loaded(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tiny_config: GuardConfig,
) -> None:
    monkeypatch.setattr("unplug.guard.prepare_active_model_spec", lambda _cfg: None)

    with caplog.at_level(logging.WARNING, logger="unplug.guard"):
        guard = Guard(config=tiny_config)

    assert guard.ml_degraded is True
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == [f"active_model=tiny configured but injection_ml is not loaded. {_FIX_HINT}"]


def test_warning_is_emitted_once_per_guard(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tiny_config: GuardConfig,
) -> None:
    """The point of the helper: neither path can log the message twice."""
    monkeypatch.setattr("unplug.guard.prepare_active_model_spec", lambda _cfg: None)

    with caplog.at_level(logging.WARNING, logger="unplug.guard"):
        Guard(config=tiny_config)

    degraded = [r for r in caplog.records if "injection_ml" in r.getMessage()]
    assert len(degraded) == 1
