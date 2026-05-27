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
