"""Resolve configured ML models for Guard runtime."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from unplug.config.guard import GuardConfig
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.versions import MODEL_VERSION_LOCAL
from unplug.ml.registry import register_ml_backends


def resolve_active_model_spec(config: GuardConfig) -> ModelSpec | None:
    if not config.active_model:
        return None
    spec = config.models.get(config.active_model)
    if spec is None:
        return None
    if isinstance(spec, ModelSpec):
        return spec
    if isinstance(spec, dict):
        return ModelSpec.model_validate(spec)
    return None


def build_model_registry() -> ModelRegistry:
    registry = ModelRegistry()
    register_ml_backends(registry)
    return registry


def load_active_model_provider(config: GuardConfig) -> ModelProvider | None:
    spec = resolve_active_model_spec(config)
    if spec is None:
        return None
    if spec.backend == "null":
        return None
    path = spec.path
    if path and not Path(path).is_dir():
        return None
    registry = build_model_registry()
    return registry.get(spec)


def model_cache_version(spec: ModelSpec | None) -> str:
    if spec is None:
        return MODEL_VERSION_LOCAL
    path = spec.path
    if path and Path(path).is_dir():
        manifest = Path(path) / "config.json"
        if manifest.is_file():
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()[:12]
            return f"span-{spec.name}-{digest}"
    return f"span-{spec.name}-{spec.version}"
