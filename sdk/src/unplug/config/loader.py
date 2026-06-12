"""Config file loading — TOML (stdlib) with env var overrides."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from unplug.config.agent_policy import (
    BoundaryConfig,
    DegradationConfig,
    IntentConfig,
    TrajectoryConfig,
)
from unplug.config.cache import CacheConfig
from unplug.config.guard import GuardConfig, PipelineConfig, ScannerConfig, ThresholdConfig
from unplug.config.limits import LimitConfig
from unplug.config.messages import MessageConfig
from unplug.config.policy import MlGateConfig, ScanPolicy
from unplug.config.tools import ToolPolicyConfig


def load_from_file(path: str | Path) -> dict[str, Any]:
    """Read a TOML config file and return the raw dict."""
    p = Path(path)
    if not p.exists():
        msg = f"Config file not found: {p}"
        raise FileNotFoundError(msg)

    with p.open("rb") as f:
        return tomllib.load(f)


def load_from_env(prefix: str = "UNPLUG_") -> dict[str, Any]:
    """Read env vars with the given prefix into a nested dict."""
    result: dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix) :].lower().split("__")
        target = result
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        raw = value
        if "," in raw:
            target[parts[-1]] = [v.strip() for v in raw.split(",")]
        else:
            target[parts[-1]] = _coerce(raw)
    return result


def _coerce(value: str) -> Any:
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _merge(base: dict, override: dict) -> dict:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _build_thresholds(data: dict[str, Any]) -> ThresholdConfig:
    return ThresholdConfig(
        **{k: float(v) for k, v in data.items() if k in ThresholdConfig.model_fields}
    )


def _build_policy(data: dict[str, Any]) -> ScanPolicy:
    return ScanPolicy(**{k: v for k, v in data.items() if k in ScanPolicy.model_fields})


def _build_pipeline(data: dict[str, Any]) -> PipelineConfig:
    kwargs: dict[str, Any] = {}
    if "thresholds" in data:
        kwargs["thresholds"] = _build_thresholds(data["thresholds"])
    if "policy" in data:
        kwargs["policy"] = _build_policy(data["policy"])
    if "fail_closed" in data:
        kwargs["fail_closed"] = data["fail_closed"]
    if "ml_gate" in data:
        kwargs["ml_gate"] = MlGateConfig(
            **{k: v for k, v in data["ml_gate"].items() if k in MlGateConfig.model_fields}
        )
    return PipelineConfig(**kwargs)


def _build_limits(data: dict[str, Any]) -> LimitConfig:
    return LimitConfig(**{k: v for k, v in data.items() if k in LimitConfig.model_fields})


def _build_messages(data: dict[str, Any]) -> MessageConfig:
    return MessageConfig(**{k: v for k, v in data.items() if k in MessageConfig.model_fields})


def _build_scanner_configs(data: dict[str, Any]) -> dict[str, ScannerConfig]:
    return {
        name: ScannerConfig(**{k: v for k, v in cfg.items() if k in ScannerConfig.model_fields})
        for name, cfg in data.items()
        if isinstance(cfg, dict)
    }


def _build_models(data: dict[str, Any]) -> dict[str, Any]:
    from unplug.core.models import ModelSpec

    models: dict[str, ModelSpec] = {}
    for name, cfg in data.items():
        if not isinstance(cfg, dict):
            continue
        models[name] = ModelSpec(
            name=str(cfg.get("name", name)),
            version=str(cfg.get("version", "latest")),
            backend=str(cfg.get("backend", "transformers_span")),
            path=cfg.get("path"),
            repo_id=cfg.get("repo_id"),
            config=dict(cfg.get("config", {})),
        )
    return models


def _build_tools(data: dict[str, Any]) -> ToolPolicyConfig:
    kwargs: dict[str, Any] = {}
    for key in ToolPolicyConfig.model_fields:
        if key in data:
            kwargs[key] = data[key]
    if "side_effect_tools" in kwargs and isinstance(kwargs["side_effect_tools"], list):
        kwargs["side_effect_tools"] = tuple(kwargs["side_effect_tools"])
    if "taint_source_tools" in kwargs and isinstance(kwargs["taint_source_tools"], list):
        kwargs["taint_source_tools"] = tuple(kwargs["taint_source_tools"])
    return ToolPolicyConfig(**kwargs)


def _build_boundaries(data: dict[str, Any]) -> BoundaryConfig:
    return BoundaryConfig(**{k: v for k, v in data.items() if k in BoundaryConfig.model_fields})


def _build_trajectory(data: dict[str, Any]) -> TrajectoryConfig:
    return TrajectoryConfig(**{k: v for k, v in data.items() if k in TrajectoryConfig.model_fields})


def _build_intent(data: dict[str, Any]) -> IntentConfig:
    return IntentConfig(**{k: v for k, v in data.items() if k in IntentConfig.model_fields})


def _build_degradation(data: dict[str, Any]) -> DegradationConfig:
    kwargs: dict[str, Any] = {k: v for k, v in data.items() if k in DegradationConfig.model_fields}
    if "high_risk_tools" in kwargs and isinstance(kwargs["high_risk_tools"], list):
        kwargs["high_risk_tools"] = tuple(kwargs["high_risk_tools"])
    return DegradationConfig(**kwargs)


def build_config(data: dict[str, Any]) -> GuardConfig:
    """Build a GuardConfig from a raw dict (from TOML or env)."""
    guard_data = data.get("guard", data)
    kwargs: dict[str, Any] = {}

    if "scanners" in guard_data and isinstance(guard_data["scanners"], list):
        kwargs["scanners"] = guard_data["scanners"]
    if "mode" in guard_data:
        kwargs["mode"] = guard_data["mode"]
    if "server_url" in guard_data:
        kwargs["server_url"] = guard_data["server_url"]
    if "server_api_key" in guard_data:
        kwargs["server_api_key"] = guard_data["server_api_key"]
    if "policy" in guard_data:
        kwargs["policy"] = _build_policy(guard_data["policy"])
    if "cache" in guard_data:
        kwargs["cache"] = CacheConfig(
            **{k: v for k, v in guard_data["cache"].items() if k in CacheConfig.model_fields}
        )
    if "fail_closed" in guard_data:
        kwargs["fail_closed"] = guard_data["fail_closed"]

    pipeline_data = guard_data.get("pipeline", data.get("pipeline", {}))
    if pipeline_data:
        kwargs["pipeline"] = _build_pipeline(pipeline_data)

    scanner_data = guard_data.get("scanners_config", data.get("scanners_config", {}))
    if not scanner_data:
        scanner_data = data.get("scanners", {})
        if isinstance(scanner_data, dict):
            scanner_data = {k: v for k, v in scanner_data.items() if isinstance(v, dict)}
        else:
            scanner_data = {}
    if scanner_data:
        kwargs["scanner_configs"] = _build_scanner_configs(scanner_data)

    limits_data = guard_data.get("limits", data.get("limits", {}))
    if limits_data:
        kwargs["limits"] = _build_limits(limits_data)

    messages_data = guard_data.get("messages", data.get("messages", {}))
    if messages_data:
        kwargs["messages"] = _build_messages(messages_data)

    if "judge_enabled" in guard_data:
        kwargs["judge_enabled"] = guard_data["judge_enabled"]
    if "judge_low" in guard_data:
        kwargs["judge_low"] = float(guard_data["judge_low"])
    if "judge_high" in guard_data:
        kwargs["judge_high"] = float(guard_data["judge_high"])

    models_data = guard_data.get("models", data.get("models", {}))
    if isinstance(models_data, dict) and models_data:
        kwargs["models"] = _build_models(models_data)
    if "active_model" in guard_data:
        kwargs["active_model"] = guard_data["active_model"]
    if "auto_download_model" in guard_data:
        kwargs["auto_download_model"] = bool(guard_data["auto_download_model"])
    if "require_ml" in guard_data:
        kwargs["require_ml"] = bool(guard_data["require_ml"])

    tools_data = guard_data.get("tools", data.get("tools", {}))
    if tools_data:
        kwargs["tools"] = _build_tools(tools_data)

    boundaries_data = guard_data.get("boundaries", data.get("boundaries", {}))
    if boundaries_data:
        kwargs["boundaries"] = _build_boundaries(boundaries_data)

    trajectory_data = guard_data.get("trajectory", data.get("trajectory", {}))
    if trajectory_data:
        kwargs["trajectory"] = _build_trajectory(trajectory_data)

    intent_data = guard_data.get("intent", data.get("intent", {}))
    if intent_data:
        kwargs["intent"] = _build_intent(intent_data)

    degradation_data = guard_data.get("degradation", data.get("degradation", {}))
    if degradation_data:
        kwargs["degradation"] = _build_degradation(degradation_data)

    return GuardConfig(**kwargs)


def load(
    file_path: str | Path | None = None,
    env_prefix: str = "UNPLUG_",
) -> GuardConfig:
    """Load config from file + env overrides, with sensible defaults."""
    file_data: dict[str, Any] = {}
    if file_path is not None:
        file_data = load_from_file(file_path)
    env_data = load_from_env(env_prefix)
    merged = _merge(file_data, env_data)
    merged = _apply_model_env_overrides(merged)
    if not merged:
        return GuardConfig()
    return build_config(merged)


def _apply_model_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Map UNPLUG_ACTIVE_MODEL / UNPLUG_MODEL_PATH into models block."""
    import os

    active = os.environ.get("UNPLUG_ACTIVE_MODEL")
    path = os.environ.get("UNPLUG_MODEL_PATH")
    if not active and not path:
        return data
    out = dict(data)
    guard = dict(out.get("guard", {}))
    models = dict(out.get("models", {}))
    tier = active or "tiny"
    if active:
        guard["active_model"] = active
    elif path:
        guard["active_model"] = tier
    if path:
        slot = dict(models.get(tier, {}))
        slot.setdefault("name", f"unplug-{tier}")
        slot.setdefault("backend", "transformers_span")
        slot["path"] = path
        models[tier] = slot
    out["guard"] = guard
    out["models"] = models
    return out
