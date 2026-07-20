"""Tests for Guard ML init and model runtime resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from unplug.config.guard import GuardConfig
from unplug.core.runtime.model_runtime import merge_catalog_models
from unplug.exceptions import ConfigError, ModelError


def test_guard_degrades_when_download_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    monkeypatch.setenv("UNPLUG_MODEL_CACHE", str(tmp_path / "cache"))

    def boom(self: object, tier: str, **kwargs: object) -> Path:
        msg = "offline"
        raise RuntimeError(msg)

    monkeypatch.setattr("unplug.ml.store.ModelStore.ensure_tier", boom)

    from unplug import Guard

    with caplog.at_level("WARNING", logger="unplug.guard"):
        guard = Guard(
            config=merge_catalog_models(
                GuardConfig(active_model="tiny", auto_download_model=True, require_ml=False)
            )
        )
    assert guard.ml_degraded is True
    assert guard.ml_model_loaded is False
    assert "pip install" in caplog.text
    assert "unplug-models download tiny" in caplog.text


def test_guard_require_ml_raises_when_download_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    monkeypatch.setenv("UNPLUG_MODEL_CACHE", str(tmp_path / "cache"))

    def boom(self: object, tier: str, **kwargs: object) -> Path:
        msg = "offline"
        raise RuntimeError(msg)

    monkeypatch.setattr("unplug.ml.store.ModelStore.ensure_tier", boom)

    from unplug import Guard

    with pytest.raises(ModelError, match="require_ml"):
        Guard(
            config=merge_catalog_models(
                GuardConfig(active_model="tiny", auto_download_model=True, require_ml=True)
            )
        )


def test_guard_unknown_active_model_raises_config_error() -> None:
    from unplug import Guard

    with pytest.raises(ConfigError, match="Valid tiers"):
        Guard(config=GuardConfig(active_model="typo", require_ml=True))
