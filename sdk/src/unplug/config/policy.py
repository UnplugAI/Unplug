"""Scan policy: span thresholds and document-level coverage gate."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

# Single source of truth for ml_gate presets. The loader and the model validator
# both read this, so a TOML config and an equivalent Python config agree.
ML_GATE_PRESETS: dict[str, dict[str, float | bool]] = {
    "recall": {"always_below_high": True, "gray_low": 0.0},
    "balanced": {"always_below_high": False, "gray_low": 0.3},
    "latency": {"always_below_high": False, "gray_low": 0.5},
}


def apply_ml_gate_preset(data: dict[str, Any]) -> dict[str, Any]:
    """Expand a preset name into the fields it stands for.

    The preset wins over sibling values, matching how the TOML loader has always
    behaved. Set the fields directly if you want to override one of them.
    """
    values = ML_GATE_PRESETS.get(str(data.get("preset", "")))
    if values is None:
        return data
    return {**data, **values}


class RedactionMode(StrEnum):
    """How malicious spans are replaced in redacted_text."""

    BLOCKED_TAGS = "blocked_tags"
    STRIP = "strip"
    REDACTED_TAGS = "redacted_tags"
    NONE = "none"


class DecisionMode(StrEnum):
    """How ML doc-head and span-head signals combine into a detection."""

    DOC_OR_SPAN = "doc_or_span"
    DOC_ONLY = "doc_only"
    DOC_GATED = "doc_gated"


class MlGateConfig(BaseModel):
    """Hybrid regex-to-ML routing: run the ML scanner only when regex is uncertain.

    Ported from the server's semantic-layer routing. Defaults preserve the
    classic behavior: always run ML below the high-confidence cutoff.
    """

    model_config = {"frozen": True}

    gray_high: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Skip ML at/above this regex risk; None = pipeline block threshold",
    )
    gray_low: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Gray-band floor: below this (and nothing flagged) ML is skipped",
    )
    always_below_high: bool = Field(
        default=False,
        description=(
            "True: second-pass every scan below gray_high (catches regex misses at risk 0). "
            "False: invoke ML only in the gray band or when regex flagged something."
        ),
    )
    preset: Literal["recall", "balanced", "latency"] | None = Field(
        default=None,
        description="Optional preset: recall=always_below_high, balanced/latency=gray-band only",
    )

    @model_validator(mode="before")
    @classmethod
    def _expand_preset(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return apply_ml_gate_preset(data)
        return data


class ScanPolicy(BaseModel):
    """Controls redact/review/block using per-span scores and flagged coverage."""

    model_config = {"frozen": True}

    block_coverage_ratio: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="BLOCK when union of flagged spans / text length >= this ratio",
    )
    redact_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    block_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Per-span high confidence; also contributes to BLOCK",
    )
    merge_overlapping_spans: bool = True
    redaction_mode: RedactionMode = Field(
        default=RedactionMode.BLOCKED_TAGS,
        description=(
            "blocked_tags=[BLOCKED:cat], strip=delete span, "
            "redacted_tags=legacy, none=no redacted_text"
        ),
    )
    abstain_enabled: bool = Field(
        default=True,
        description="Use ML abstain band when injection_ml is active",
    )
    tau_abstain_low: float = Field(
        default=0.35,
        ge=0.0,
        le=1.0,
        description="Doc score below this (and no span fire) -> ALLOW band",
    )
    decision_mode: DecisionMode = Field(
        default=DecisionMode.DOC_OR_SPAN,
        description="How ML doc/span heads combine: doc_or_span | doc_only | doc_gated",
    )
    tau_doc_gate: float = Field(
        default=0.99,
        ge=0.0,
        le=1.0,
        description=(
            "DOC_GATED only: doc score alone (no span corroboration) detects at/above "
            "this second, higher bar; values <= tau_doc make the gate a no-op"
        ),
    )
    sensitive_context_enabled: bool = Field(
        default=True,
        description="Boost injection/leakage scores when tokens/secrets appear in text",
    )
    sensitive_context_boost: float = Field(
        default=0.2,
        ge=0.0,
        le=0.5,
        description="Score added to injection/leakage findings in sensitive context",
    )
    sensitive_context_block_delta: float = Field(
        default=0.15,
        ge=0.0,
        le=0.5,
        description="Lower block_threshold by this amount in sensitive context",
    )
    abstain_is_safe: bool = Field(
        default=False,
        description=(
            "When true, Action.ABSTAIN sets ScanResult.safe=True (legacy pass-through). "
            "Default false: uncertain ML band is not safe for model context."
        ),
    )
    scan_user_secrets: bool = Field(
        default=True,
        description="Scan USER-trust input for API keys and secret-shaped tokens only",
    )
