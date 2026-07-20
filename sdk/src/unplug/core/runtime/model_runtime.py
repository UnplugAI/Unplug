"""Resolve configured ML models for Guard runtime."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from unplug.config.guard import GuardConfig
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL
from unplug.exceptions import ConfigError, ModelError
from unplug.ml.catalog import catalog_model_spec, load_catalog
from unplug.ml.registry import register_ml_backends
from unplug.ml.store import ModelStore


def merge_catalog_models(config: GuardConfig) -> GuardConfig:
    """Inject catalog defaults for tiers missing from user config."""
    cat = load_catalog()
    models = dict(config.models)
    for tier_id, entry in cat.tiers.items():
        if tier_id not in models:
            models[tier_id] = entry.to_model_spec()
    return config.model_copy(update={"models": models})


def resolve_active_model_spec(config: GuardConfig) -> ModelSpec | None:
    if not config.active_model:
        return None
    spec = config.models.get(config.active_model)
    if spec is None:
        fallback = catalog_model_spec(config.active_model)
        if fallback is None:
            cat = load_catalog()
            valid = ", ".join(cat.tier_names())
            raise ConfigError(
                f"Unknown active_model tier {config.active_model!r}. Valid tiers: {valid}"
            )
        spec = fallback
    if isinstance(spec, dict):
        spec = ModelSpec.model_validate(spec)
    if not isinstance(spec, ModelSpec):
        return None
    return spec


def prepare_active_model_spec(config: GuardConfig) -> ModelSpec | None:
    """Resolve spec and optionally download into the local cache."""
    cfg = merge_catalog_models(config)
    spec = resolve_active_model_spec(cfg)
    if spec is None:
        return None

    store = ModelStore()
    tier = config.active_model or ""
    spec = store.resolve_spec_path(spec, tier=tier)

    path = spec.path
    if path and store.is_valid_checkpoint(Path(path)):
        return spec

    if not config.auto_download_model:
        return spec

    if not spec.repo_id and tier:
        cat = load_catalog()
        entry = cat.get(tier)
        if entry is not None:
            spec = spec.model_copy(update={"repo_id": entry.repo_id})

    if not spec.repo_id:
        return spec

    try:
        ckpt = store.ensure_tier(tier, entry=load_catalog().get(tier))
    except ConfigError as exc:
        raise ModelError(str(exc)) from exc
    except Exception as exc:
        raise ModelError(
            f"Failed to download model tier {tier!r}. "
            f"Set UNPLUG_MODEL_PATH to a local checkpoint or run: unplug-models download {tier}"
        ) from exc

    return spec.model_copy(update={"path": str(ckpt)})


def build_model_registry() -> ModelRegistry:
    registry = ModelRegistry()
    register_ml_backends(registry)
    return registry


def load_active_model_provider(
    config: GuardConfig,
    *,
    spec: ModelSpec | None = None,
) -> ModelProvider | None:
    resolved = spec if spec is not None else prepare_active_model_spec(config)
    if resolved is None:
        return None
    if resolved.backend == "null":
        return None
    path = resolved.path
    if not path or not Path(path).is_dir():
        if config.require_ml:
            tier = config.active_model or "unknown"
            msg = (
                f"Model tier {tier!r} is not available locally. Run: unplug-models download {tier}"
            )
            raise ModelError(msg)
        return None
    registry = build_model_registry()
    return registry.get(resolved)


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


def active_model_status(config: GuardConfig | None = None) -> dict[str, object]:
    """Summary for CLI / diagnostics."""
    from unplug.config.loader import load

    cfg = config or load()
    cfg = merge_catalog_models(cfg)
    store = ModelStore()
    return {
        "active_model": cfg.active_model,
        "auto_download_model": cfg.auto_download_model,
        "require_ml": cfg.require_ml,
        "cache_root": str(store.cache_root),
        "env_model_path": os.environ.get("UNPLUG_MODEL_PATH"),
        "tiers": store.list_status(),
    }
