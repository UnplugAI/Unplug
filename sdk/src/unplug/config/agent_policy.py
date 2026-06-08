"""Agent-host policy: boundaries, risk trajectory, intent verification."""

from __future__ import annotations

from pydantic import BaseModel, Field


class BoundaryConfig(BaseModel):
    """OpenClaw-style untrusted content wrapping before scan / LLM context."""

    model_config = {"frozen": True}

    auto_wrap_untrusted: bool = True
    sanitize_before_wrap: bool = True
    strip_on_output: bool = False


class TrajectoryConfig(BaseModel):
    """Crescendo detection — escalating risk scores across a session."""

    model_config = {"frozen": True}

    enabled: bool = True
    window: int = Field(default=5, ge=2, le=20)
    min_samples: int = Field(default=3, ge=2, le=20)
    review_slope: float = Field(default=0.08, description="Avg score increase per step → REVIEW")
    block_slope: float = Field(default=0.15, description="Avg score increase per step → BLOCK")


class IntentConfig(BaseModel):
    """Semantic intent vs tool-call mismatch (CaMeL / OpenClaw gate)."""

    model_config = {"frozen": True}

    enabled: bool = True
    review_score: float = 0.72


class ToolChainConfig(BaseModel):
    """Session tool-sequence kill-chain detection."""

    model_config = {"frozen": True}

    enabled: bool = True
    history_size: int = Field(default=20, ge=3, le=100)


class CollusionConfig(BaseModel):
    """Multi-agent collusion — pair message frequency and cross-agent exfil."""

    model_config = {"frozen": True}

    enabled: bool = True
    window_seconds: float = Field(default=60.0, ge=1.0, le=600.0)
    pair_message_threshold: int = Field(default=10, ge=2, le=100)
    cross_agent_window_seconds: float = Field(default=120.0, ge=1.0, le=600.0)


# OpenClaw: limit exec / browser / web when blast radius must shrink.
DEFAULT_HIGH_RISK_TOOL_PATTERNS: tuple[str, ...] = (
    r"^exec",
    r"^shell",
    r"^bash",
    r"^run_terminal",
    r"^run_command",
    r"^terminal",
    r"^browser",
    r"^web_fetch",
    r"^web_search",
    r"^osascript",
    r"^python",
    r"^node",
)


class DegradationConfig(BaseModel):
    """Homeostasis-style adaptive tightening after trajectory / crescendo signals."""

    model_config = {"frozen": True}

    enabled: bool = True
    high_risk_patterns: tuple[str, ...] = DEFAULT_HIGH_RISK_TOOL_PATTERNS
    high_risk_tools: tuple[str, ...] = Field(default_factory=tuple)
    review_at_level: int = Field(default=1, ge=1, le=3)
    block_at_level: int = Field(default=2, ge=2, le=5)
    review_score: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Below pipeline block threshold (0.8) so level-1 yields REVIEW",
    )
    block_score: float = Field(default=0.92, ge=0.0, le=1.0)
