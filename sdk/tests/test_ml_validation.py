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
    assert "checkpoint_relative" in data
    assert data["catalog_config"]["inj_threshold"] == 0.45
    assert data["catalog_config"]["doc_threshold"] == 0.9


def test_catalog_toml_matches_manifest_thresholds() -> None:
    manifest = catalog_config_from_manifest()
    cat = load_catalog()
    tiny = cat.tiers["tiny"]
    assert tiny.config["inj_threshold"] == manifest["inj_threshold"]
    assert tiny.config["doc_threshold"] == manifest["doc_threshold"]
    assert tiny.config["max_length"] == manifest["max_length"]


def test_resolve_checkpoint_without_weights() -> None:
    ckpt = resolve_validation_checkpoint(require_weights=False)
    if ckpt is None:
        pytest.skip("checkpoint directory not in workspace")
    assert is_valid_checkpoint(ckpt, require_weights=False)
    assert (ckpt / "config.json").is_file()


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
