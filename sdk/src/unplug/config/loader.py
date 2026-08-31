"""Config file loading: TOML (stdlib) with env var overrides."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from unplug.config.agent_policy import (
    BoundaryConfig,
    CollusionConfig,
    DegradationConfig,
    IntentConfig,
    ToolChainConfig,
    TrajectoryConfig,
)
from unplug.config.cache import CacheConfig
from unplug.config.guard import GuardConfig, PipelineConfig, ScannerConfig, ThresholdConfig
from unplug.config.limits import LimitConfig
from unplug.config.messages import MessageConfig
from unplug.config.policy import MlGateConfig, ScanPolicy, apply_ml_gate_preset
from unplug.config.tools import ToolPolicyConfig
from unplug.exceptions import ConfigError

_GUARD_SECTION_KEYS: frozenset[str] = frozenset(
    {
        "scanners",
        "mode",
        "server_url",
        "server_api_key",
        "policy",
        "cache",
        "fail_closed",
        "pipeline",
        "scanners_config",
        "limits",
        "messages",
        "judge_enabled",
        "judge_low",
        "judge_high",
        "models",
        "active_model",
        "auto_download_model",
        "require_ml",
        "tools",
        "boundaries",
        "trajectory",
        "intent",
        "degradation",
        "toolchain",
        "collusion",
        "strict_scanner_allowlist",
    }
)


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "yes", "1"):
            return True
        if lowered in ("false", "no", "0"):
            return False
    return bool(value)


def _reject_unknown_guard_keys(data: dict[str, Any]) -> None:
    if "guard" not in data:
        return
    guard = data["guard"]
    if not isinstance(guard, dict):
        msg = "[guard] must be a table"
        raise ConfigError(msg)
    unknown = sorted(set(guard) - _GUARD_SECTION_KEYS)
    if unknown:
        msg = f"Unknown [guard] config keys: {', '.join(unknown)}"
        raise ConfigError(msg)


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


def _apply_ml_gate_preset(data: dict[str, Any]) -> dict[str, Any]:
    """Kept for callers that expand a preset before building the model."""
    return apply_ml_gate_preset(data)


def _build_pipeline(data: dict[str, Any]) -> PipelineConfig:
    kwargs: dict[str, Any] = {}
    if "thresholds" in data:
        kwargs["thresholds"] = _build_thresholds(data["thresholds"])
    if "policy" in data:
        kwargs["policy"] = _build_policy(data["policy"])
    if "fail_closed" in data:
        import warnings

        warnings.warn(
            "pipeline.fail_closed is deprecated and ignored; scanner/pipeline errors always block",
            DeprecationWarning,
            stacklevel=2,
        )
    if "judge_timeout" in data:
        import warnings

        warnings.warn(
            "pipeline.judge_timeout is deprecated and ignored; removed in v1.0",
            DeprecationWarning,
            stacklevel=2,
        )
    if "ml_gate" in data:
        ml_gate_data = _apply_ml_gate_preset(data["ml_gate"])
        kwargs["ml_gate"] = MlGateConfig(
            **{k: v for k, v in ml_gate_data.items() if k in MlGateConfig.model_fields}
        )
    pipeline = PipelineConfig(**kwargs)
    if "thresholds" in data and "policy" not in data:
        # Only when this table did not name a policy of its own: an explicit
        # [pipeline.policy] is the more specific statement and used to be
        # silently overwritten here.
        #
        # Constructed, not `model_copy(update=...)`. model_copy writes the value
        # in unchecked, which is how a block of 5.0 reached pipeline.policy and
        # made every score decide ALLOW.
        t = pipeline.thresholds
        policy = ScanPolicy(
            **{
                **pipeline.policy.model_dump(),
                "block_threshold": t.block,
                "redact_threshold": t.redact,
                "review_threshold": t.review,
            }
        )
        pipeline = pipeline.model_copy(update={"policy": policy})
    return pipeline


def _build_limits(data: dict[str, Any]) -> LimitConfig:
    return LimitConfig(**{k: v for k, v in data.items() if k in LimitConfig.model_fields})


def _build_messages(data: dict[str, Any]) -> MessageConfig:
    return MessageConfig(**{k: v for k, v in data.items() if k in MessageConfig.model_fields})


def _build_scanner_configs(data: dict[str, Any]) -> dict[str, ScannerConfig]:
    """Per-scanner overrides, applied on top of the bundled defaults.

    `data/defaults/scanners.toml` describes itself as something you override per
    key, so a table naming one field has to leave the rest of that scanner alone.
    Building a fresh `ScannerConfig` from the subset dropped every unnamed field
    to the pydantic class default instead, which moved `secrets` from 0.99 to
    0.85 and turned `injection` normalization off for anyone who set only
    `base_score`. Both silent, both in the weakening direction.

    A scanner with no bundled entry keeps the old behaviour, since there is
    nothing to merge onto.
    """
    from unplug.data.maps_loader import default_scanner_config

    out: dict[str, ScannerConfig] = {}
    for name, cfg in data.items():
        if not isinstance(cfg, dict):
            continue
        overrides = {k: v for k, v in cfg.items() if k in ScannerConfig.model_fields}
        try:
            base = default_scanner_config(name)
        except KeyError:
            out[name] = ScannerConfig(**overrides)
            continue
        # Constructed, not `model_copy(update=...)`: model_copy writes the value
        # straight in, so a mistyped or out-of-range override would land as a
        # scan-time error instead of a config error. Merging the dumped defaults
        # keeps the bundled values while every field still goes through pydantic.
        out[name] = ScannerConfig(**{**base.model_dump(), **overrides})
    return out


def _build_models(data: dict[str, Any]) -> dict[str, Any]:
    from unplug.ml.models import ModelSpec

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


def _build_toolchain(data: dict[str, Any]) -> ToolChainConfig:
    return ToolChainConfig(**{k: v for k, v in data.items() if k in ToolChainConfig.model_fields})


def _build_collusion(data: dict[str, Any]) -> CollusionConfig:
    return CollusionConfig(**{k: v for k, v in data.items() if k in CollusionConfig.model_fields})


def build_config(data: dict[str, Any]) -> GuardConfig:
    """Build a GuardConfig from a raw dict (from TOML or env)."""
    _reject_unknown_guard_keys(data)
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

    # Top-level fallback, as `pipeline`, `limits`, `messages`, `tools` and
    # `boundaries` all already have. `unplug.example.toml` ships `[policy]` at
    # top level, so without this the whole block is dead for anyone who copied
    # the example: thresholds, abstain, decision mode and the sensitive-context
    # switches all silently keep their defaults.
    # Merged per key rather than whole-table, so a partial [guard.policy] does
    # not discard a top-level [policy] that names different settings. [guard]
    # wins wherever both name the same key, since it is the more specific place
    # to say it and it is what Guard already honoured.
    def _policy_table(source: dict[str, Any], label: str) -> dict[str, Any]:
        # Present but not a table is a mistake, not an absence. Treating it as {}
        # boots a Guard on default thresholds when the operator thought they had
        # set them, which is the fail-open version of the bug this whole change
        # is about. On dev this raised, and it should keep raising.
        if label not in source:
            return {}
        value = source[label]
        if not isinstance(value, dict):
            msg = f"[{label}] must be a table, got {type(value).__name__}"
            raise ConfigError(msg)
        return value

    # Precedence, least to most specific: [pipeline.policy], [policy], [guard.policy].
    # [pipeline.thresholds] is folded in further down and fills only what none of
    # these named.
    _pipeline_table = guard_data.get("pipeline", data.get("pipeline", {}))
    pipeline_policy = (
        _policy_table(_pipeline_table, "policy") if isinstance(_pipeline_table, dict) else {}
    )
    top_policy = _policy_table(data, "policy")
    guard_policy = _policy_table(guard_data, "policy")
    policy_data: dict[str, Any] = {
        **(pipeline_policy or {}),
        **(top_policy or {}),
        **(guard_policy or {}),
    }
    if policy_data:
        kwargs["policy"] = _build_policy(policy_data)
    if "cache" in guard_data:
        kwargs["cache"] = CacheConfig(
            **{k: v for k, v in guard_data["cache"].items() if k in CacheConfig.model_fields}
        )
    if "fail_closed" in guard_data:
        kwargs["fail_closed"] = guard_data["fail_closed"]
    if "strict_scanner_allowlist" in guard_data:
        kwargs["strict_scanner_allowlist"] = _coerce_bool(guard_data["strict_scanner_allowlist"])

    pipeline_data = guard_data.get("pipeline", data.get("pipeline", {}))
    if pipeline_data:
        kwargs["pipeline"] = _build_pipeline(pipeline_data)
        # `_build_pipeline` folds `[pipeline.thresholds]` into `pipeline.policy`,
        # and nothing scans with that policy: `Guard` builds every request policy
        # from the guard-level one, and `BasePipeline._resolve_policy` prefers the
        # context policy over `self._config.policy`. A pipeline run without a
        # context is the only path that saw the thresholds, and the public API
        # never takes it, so the same file gave `Guard.scan` and `Pipeline.run`
        # two different actions for one input.
        #
        # Folding them into the guard policy as well makes one policy govern.
        # `[policy]` wins on any key it names, since it is the more specific
        # place to say it and it is what `Guard` already honoured.
        thresholds = pipeline_data.get("thresholds")
        if isinstance(thresholds, dict):
            named = {
                field: thresholds[key]
                for key, field in (
                    ("block", "block_threshold"),
                    ("redact", "redact_threshold"),
                    ("review", "review_threshold"),
                )
                if key in thresholds
            }
            explicit = policy_data if isinstance(policy_data, dict) else {}
            named = {k: v for k, v in named.items() if k not in explicit}
            if named:
                # Same reason as the scanner overrides above: these values come
                # straight out of the raw TOML, and block/redact/review are
                # declared ge=0.0 le=1.0. `model_copy` would install a string or
                # a 5.0 unchecked.
                base = kwargs.get("policy") or ScanPolicy()
                kwargs["policy"] = ScanPolicy(**{**base.model_dump(), **named})

    # One file must not produce two block bars. Folding the thresholds up into the
    # guard policy fixed the direction Guard.scan reads, but left pipeline.policy
    # and pipeline.thresholds holding whatever [pipeline] said, so [policy]
    # block_threshold = 0.9 next to [pipeline.thresholds] block = 0.2 gave
    # Guard.scan REDACT, a bare Pipeline.run BLOCK, and the ML gate a gray_high of
    # 0.2. Push the resolved policy back down so all three agree.
    #
    # Outside the [pipeline] branch on purpose: a file with [policy] and no
    # [pipeline] table at all still has to reconcile, and running this only when
    # [pipeline] was present left exactly that case split.
    #
    # This does not take away the independent ML cutoff. The only consumer of
    # pipeline.thresholds is the gate's fallback block threshold, and
    # pipeline.ml_gate.gray_high still overrides it.
    resolved_policy = kwargs.get("policy")
    if resolved_policy is not None:
        built = kwargs.get("pipeline") or PipelineConfig()
        kwargs["pipeline"] = built.model_copy(
            update={
                "policy": resolved_policy,
                "thresholds": ThresholdConfig(
                    block=resolved_policy.block_threshold,
                    redact=resolved_policy.redact_threshold,
                    review=resolved_policy.review_threshold,
                ),
            }
        )

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
        import warnings

        warnings.warn(
            "judge_enabled is deprecated and ignored; pass judge= to Guard() (removed in v1.0)",
            DeprecationWarning,
            stacklevel=2,
        )
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

    toolchain_data = data.get("toolchain", guard_data.get("toolchain", {}))
    if toolchain_data:
        kwargs["toolchain"] = _build_toolchain(toolchain_data)

    collusion_data = data.get("collusion", guard_data.get("collusion", {}))
    if collusion_data:
        kwargs["collusion"] = _build_collusion(collusion_data)

    if guard_data.get("fail_closed") is False or data.get("guard", {}).get("fail_closed") is False:
        import warnings

        warnings.warn(
            "fail_closed=false is deprecated and ignored; scanner/pipeline errors always block",
            DeprecationWarning,
            stacklevel=2,
        )

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
    # After the model overrides, not before: UNPLUG_ACTIVE_MODEL creates a [guard]
    # table where the file had none, which would otherwise strand the flat keys again.
    merged = _apply_model_env_overrides(merged)
    merged = _promote_flat_env_keys(merged, env_data)
    if not merged:
        return GuardConfig()
    return build_config(merged)


def _promote_flat_env_keys(data: dict[str, Any], env_data: dict[str, Any]) -> dict[str, Any]:
    """Move flat UNPLUG_* settings into [guard] when the file uses a [guard] table.

    ``load_from_env`` writes UNPLUG_REQUIRE_ML at the top level, but ``build_config``
    reads every guard setting through ``data["guard"]`` as soon as that table exists.
    So the variables the README tells people to export were silently dropped by anyone
    who had copied unplug.example.toml, which has a [guard] table (#168). Only two of
    them, ACTIVE_MODEL and MODEL_PATH, escaped, because they are hand-written into the
    table by _apply_model_env_overrides.

    Environment wins over the file, matching _merge. The explicit nested form
    UNPLUG_GUARD__X wins over the flat one, since it says exactly where it belongs.
    """
    if "guard" not in data or not isinstance(data["guard"], dict):
        return data
    env_guard = env_data.get("guard")
    already_set = set(env_guard) if isinstance(env_guard, dict) else set()

    promoted = {
        key: value
        for key, value in env_data.items()
        if key in GuardConfig.model_fields
        and key not in already_set
        and not isinstance(value, dict)
    }
    if not promoted:
        return data

    out = dict(data)
    out["guard"] = {**out["guard"], **promoted}
    return out


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
