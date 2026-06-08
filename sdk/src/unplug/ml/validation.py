"""Resolve ML validation paths from configs/ml_validation.json."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any


def sdk_root() -> Path:
    return Path(__file__).resolve().parents[3]


def workspace_root() -> Path:
    env = os.environ.get("UNPLUG_WORKSPACE_ROOT")
    if env:
        return Path(env)
    return sdk_root().parent.parent


def manifest_path() -> Path:
    return sdk_root() / "configs" / "ml_validation.json"


@lru_cache(maxsize=1)
def load_ml_validation_manifest() -> dict[str, Any]:
    path = manifest_path()
    if not path.is_file():
        msg = f"ML validation manifest not found: {path}"
        raise FileNotFoundError(msg)
    return json.loads(path.read_text(encoding="utf-8"))


def is_valid_checkpoint(path: Path, *, require_weights: bool = False) -> bool:
    if not path.is_dir() or not (path / "config.json").is_file():
        return False
    if not require_weights:
        return True
    manifest = load_ml_validation_manifest()
    return any((path / name).is_file() for name in manifest.get("optional_weight_files", []))


def resolve_validation_checkpoint(*, require_weights: bool = False) -> Path | None:
    for env_name in ("UNPLUG_TEST_CHECKPOINT", "UNPLUG_MODEL_PATH"):
        raw = os.environ.get(env_name)
        if raw:
            candidate = Path(raw)
            if is_valid_checkpoint(candidate, require_weights=require_weights):
                return candidate

    manifest = load_ml_validation_manifest()
    candidate = workspace_root() / str(manifest["checkpoint_relative"])
    if is_valid_checkpoint(candidate, require_weights=require_weights):
        return candidate
    if not require_weights and is_valid_checkpoint(candidate, require_weights=False):
        return candidate
    return None


def resolve_thresholds_path() -> Path | None:
    manifest = load_ml_validation_manifest()
    path = workspace_root() / str(manifest["thresholds_relative"])
    return path if path.is_file() else None


def catalog_config_from_manifest() -> dict[str, Any]:
    manifest = load_ml_validation_manifest()
    return dict(manifest.get("catalog_config", {}))
