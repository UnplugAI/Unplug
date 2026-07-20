"""Guard and pipeline configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from unplug.config.agent_policy import (
    BoundaryConfig,
    CollusionConfig,
    DegradationConfig,
    IntentConfig,
    ToolChainConfig,
    TrajectoryConfig,
)
from unplug.config.cache import CacheConfig
from unplug.config.limits import LimitConfig
from unplug.config.messages import MessageConfig
from unplug.config.policy import MlGateConfig, ScanPolicy
from unplug.config.tools import ToolPolicyConfig

MANDATORY_INPUT_SCANNERS: frozenset[str] = frozenset({"injection", "destructive"})


def resolve_input_scanners(
    requested: list[str] | None,
    *,
    strict: bool = False,
) -> list[str] | None:
    """Union mandatory input scanners; never allow dropping injection/destructive."""
    if requested is None:
        return None
    omitted = MANDATORY_INPUT_SCANNERS - set(requested)
    if omitted and strict:
        from unplug.exceptions import ConfigError

        msg = f"scan request omitted mandatory scanners: {', '.join(sorted(omitted))}"
        raise ConfigError(msg)
    merged = list(dict.fromkeys([*requested, *sorted(MANDATORY_INPUT_SCANNERS)]))
    if omitted:
        from unplug.core.runtime.logging import get_logger

        get_logger("guard").warning(
            "scan request omitted mandatory scanners %s; merged into allowlist",
            sorted(omitted),
        )
    return merged


class ThresholdConfig(BaseModel):
    """Action thresholds for deciding ALLOW/REVIEW/REDACT/BLOCK."""

    model_config = {"frozen": True}

    block: float = 0.8
    redact: float = 0.5
    review: float = 0.3


class ScannerConfig(BaseModel):
    """Per-safeguard configuration."""

    model_config = {"frozen": True}

    base_score: float = 0.85
    trust_boost: float = 0.10
    enabled: bool = True
    normalize: bool = False


class PipelineConfig(BaseModel):
    """Pipeline-level configuration."""

    model_config = {"frozen": True}

    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    policy: ScanPolicy = Field(default_factory=ScanPolicy)
    ml_gate: MlGateConfig = Field(
        default_factory=MlGateConfig,
        description="Hybrid regex-to-ML routing for the injection_ml second pass",
    )


class GuardConfig(BaseModel):
    """Top-level configuration for the Guard."""

    scanners: list[str] = Field(
        default_factory=lambda: ["injection", "destructive", "leakage", "harmful", "urls"]
    )
    strict_scanner_allowlist: bool = Field(
        default=False,
        description="Raise ConfigError when scan_request omits mandatory input scanners",
    )
    mode: str = "local"
    server_url: str | None = None
    server_api_key: str | None = None
    fail_closed: bool = True
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    policy: ScanPolicy = Field(
        default_factory=ScanPolicy,
        description="Default scan policy; per-request overrides via ScanRequest",
    )
    cache: CacheConfig = Field(default_factory=CacheConfig)
    scanner_configs: dict[str, ScannerConfig] = Field(default_factory=dict)
    limits: LimitConfig = Field(default_factory=LimitConfig)
    messages: MessageConfig = Field(default_factory=MessageConfig)
    judge_low: float = 0.3
    judge_high: float = 0.8
    models: dict[str, Any] = Field(
        default_factory=dict,
        description="Named ModelSpec entries (see unplug.ml.models.ModelSpec)",
    )
    active_model: str | None = Field(
        default=None,
        description="Model tier key from data/catalog.toml (default tier: tiny)",
    )
    auto_download_model: bool = Field(
        default=False,
        description="Download active_model from Hugging Face when not cached locally",
    )
    require_ml: bool = Field(
        default=False,
        description="Raise at Guard init if active_model cannot be loaded",
    )
    tools: ToolPolicyConfig = Field(
        default_factory=ToolPolicyConfig,
        description="Side-effect / taint-source tool classification for session policy",
    )
    boundaries: BoundaryConfig = Field(
        default_factory=BoundaryConfig,
        description="OpenClaw-style untrusted content boundary wrapping",
    )
    trajectory: TrajectoryConfig = Field(
        default_factory=TrajectoryConfig,
        description="Crescendo detection from session risk trajectory",
    )
    intent: IntentConfig = Field(
        default_factory=IntentConfig,
        description="User intent vs side-effect tool mismatch checks",
    )
    degradation: DegradationConfig = Field(
        default_factory=DegradationConfig,
        description="Homeostasis-style tightening of high-risk tools after crescendo",
    )
    toolchain: ToolChainConfig = Field(
        default_factory=ToolChainConfig,
        description="Session tool-sequence kill-chain detection",
    )
    collusion: CollusionConfig = Field(
        default_factory=CollusionConfig,
        description="Multi-agent pair frequency and cross-agent exfil detection",
    )

    def get_scanner_config(self, name: str) -> ScannerConfig:
        return self.scanner_configs.get(name, ScannerConfig())

    @classmethod
    def from_file(cls, path: str | Path) -> GuardConfig:
        from unplug.config.loader import load

        return load(file_path=path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardConfig:
        from unplug.config.loader import build_config

        return build_config(data)
