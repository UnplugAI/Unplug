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
