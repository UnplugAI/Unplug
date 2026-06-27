"""Tests for ML validation manifest and checkpoint resolution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unplug.ml.catalog import load_catalog
from unplug.ml.validation import (
    catalog_config_from_manifest,
    is_valid_checkpoint,
    load_ml_validation_manifest,
    manifest_path,
    resolve_thresholds_path,
    resolve_validation_checkpoint,
    sdk_root,
    workspace_root,
)


def test_manifest_exists_and_parses() -> None:
    path = manifest_path()
    assert path.is_file()
    data = load_ml_validation_manifest()
    assert data["tier"] == "tiny"
    assert "required_files" in data
    assert "catalog_config" not in data


def test_catalog_config_from_manifest_matches_catalog() -> None:
    manifest = catalog_config_from_manifest()
    cat = load_catalog()
    tiny = cat.tiers["tiny"]
    assert tiny.config["inj_threshold"] == manifest["inj_threshold"]
    assert tiny.config["doc_threshold"] == manifest["doc_threshold"]
    assert tiny.config["max_length"] == manifest["max_length"]


def test_catalog_config_from_manifest_missing_catalog_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-catalog.toml"

    def _missing_catalog() -> None:
        raise FileNotFoundError(f"Model catalog not found: {missing}")

    monkeypatch.setattr("unplug.ml.catalog.load_catalog", _missing_catalog)
    assert catalog_config_from_manifest() == {}


def test_resolve_checkpoint_without_weights() -> None:
    ckpt = resolve_validation_checkpoint(require_weights=False)
    if ckpt is None:
        pytest.skip("checkpoint directory not in workspace")
    assert is_valid_checkpoint(ckpt, require_weights=False)
    assert (ckpt / "config.json").is_file()


def test_resolve_checkpoint_missing_manifest_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # A wheel/non-editable install can ship without configs/ml_validation.json.
    # The resolver must return None (never raise) so module-level skipif decorators
    # degrade to a clean skip instead of crashing pytest collection at import time.
    monkeypatch.delenv("UNPLUG_TEST_CHECKPOINT", raising=False)
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        "unplug.ml.validation.manifest_path",
        lambda: Path("/no/such/dir/ml_validation.json"),
    )
    load_ml_validation_manifest.cache_clear()
    try:
        assert resolve_validation_checkpoint(require_weights=False) is None
        assert resolve_validation_checkpoint(require_weights=True) is None
    finally:
        load_ml_validation_manifest.cache_clear()


@pytest.mark.requires_ml_weights
def test_resolve_checkpoint_with_weights(ml_checkpoint_with_weights: Path) -> None:
    assert is_valid_checkpoint(ml_checkpoint_with_weights, require_weights=True)
    assert (ml_checkpoint_with_weights / "model.safetensors").is_file() or (
        ml_checkpoint_with_weights / "pytorch_model.bin"
    ).is_file()


def test_thresholds_v13_path_when_present() -> None:
    path = resolve_thresholds_path()
    if path is None:
        pytest.skip("thresholds_v13.json not in workspace")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_workspace_root_contains_sdk() -> None:
    assert (sdk_root() / "pyproject.toml").is_file()
    assert workspace_root().is_dir()
