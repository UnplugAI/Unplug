"""Scan policy — span thresholds and document-level coverage gate."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


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
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Gray-band floor: below this (and nothing flagged) ML is skipped",
    )
    always_below_high: bool = Field(
        default=True,
        description=(
            "True: second-pass every scan below gray_high (catches regex misses at risk 0). "
            "False: invoke ML only in the gray band or when regex flagged something."
        ),
    )


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
