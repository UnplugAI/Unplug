"""Pytest hooks: suppress third-party noise from optional ML stack imports."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from unplug.ml.validation import resolve_validation_checkpoint


def pytest_configure(config: object) -> None:
    """Apply filters before collection imports torch/transformers."""
    del config
    warnings.filterwarnings("ignore", category=DeprecationWarning, module=r"torch\.jit\._script")
    warnings.filterwarnings(
        "ignore",
        message=r"builtin type .* has no __module__ attribute",
        category=DeprecationWarning,
    )
    warnings.filterwarnings(
        "ignore",
        message=r"unplug\.scanners\..* is deprecated",
        category=DeprecationWarning,
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    # resolve_validation_checkpoint returns None (never raises) when the manifest
    # is missing, so a wheel/non-editable install degrades to a skip here and in
    # the module-level skipif decorators rather than crashing collection.
    if resolve_validation_checkpoint(require_weights=True) is None:
        skip_ml = pytest.mark.skip(reason="ML checkpoint weights not available")
        for item in items:
            if "requires_ml_weights" in item.keywords:
                item.add_marker(skip_ml)

    if not _docker_e2e_enabled():
        deselected: list[pytest.Item] = []
        keep: list[pytest.Item] = []
        for item in items:
            if "requires_docker" in item.keywords:
                deselected.append(item)
            else:
                keep.append(item)
        if deselected:
            config.hook.pytest_deselected(items=deselected)
            items[:] = keep


def _docker_e2e_enabled() -> bool:
    import os

    return os.environ.get("RUN_DOCKER_E2E", "").strip() in {"1", "true", "yes"}


@pytest.fixture(autouse=True)
def _isolate_model_cache(
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    """Point UNPLUG_MODEL_CACHE at an empty directory for every test.

    Without this the suite reads whatever is in the developer's real
    ~/.cache/unplug/models, so cache-dependent behaviour passes on CI (empty
    cache) and fails locally, or the reverse. Tests that want a populated cache
    build one under tmp_path and set the variable themselves; tests that need
    the machine cache opt out with @pytest.mark.real_model_cache (#163).
    """
    if request.node.get_closest_marker("real_model_cache") is not None:
        return
    empty = tmp_path_factory.mktemp("empty_model_cache")
    monkeypatch.setenv("UNPLUG_MODEL_CACHE", str(empty))
    # The cache variable alone is not isolation. resolve_spec_path prefers
    # UNPLUG_MODEL_PATH over the cache entirely, so a developer with one exported
    # (or a module fixture that sets it and never tears it down) still reaches a
    # real checkpoint and the empty cache above measures nothing.
    #
    # UNPLUG_TEST_CHECKPOINT is deliberately left alone. It is the harness's own
    # way of pointing the encoding probes and ML validation at a checkpoint, so
    # clearing it does not close a hole, it just turns those tests off.
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)


@pytest.fixture(scope="session")
def ml_checkpoint() -> Path:
    path = resolve_validation_checkpoint(require_weights=False)
    if path is None:
        pytest.skip("ML checkpoint not available")
    return path


@pytest.fixture(scope="session")
def ml_checkpoint_with_weights() -> Path:
    path = resolve_validation_checkpoint(require_weights=True)
    if path is None:
        pytest.skip("ML checkpoint weights not available")
    return path
