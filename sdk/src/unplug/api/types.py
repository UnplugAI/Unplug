"""Wire types shared by SDK and server."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, Field, model_validator

from unplug.api.enums import Action, Source
from unplug.config.policy import RedactionMode


class Finding(BaseModel):
    category: str = Field(description="Scanner category")
    subcategory: str = Field(description="Specific threat type")
    stage: str = Field(description="Pipeline stage: regex, classifier, llm_judge")
    span_start: int = Field(ge=0, description="Start offset in original text")
    span_end: int = Field(ge=0, description="End offset in original text")
    score: float = Field(ge=0.0, le=1.0, description="Confidence score")
    evidence: str = Field(description="Human-readable explanation")
    replacement: str | None = Field(default=None)

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.span_start > self.span_end:
            msg = f"span_start ({self.span_start}) must be <= span_end ({self.span_end})"
            raise ValueError(msg)
        return self


class ApprovalRequest(BaseModel):
    """Payload for host/UI when a tool call needs operator approval."""

    tool_name: str
    arguments: dict = Field(default_factory=dict)
    reason: str
    risk_score: float = Field(ge=0.0, le=1.0)
    action: Action = Action.REVIEW
    findings: list[str] = Field(default_factory=list)
    session_tainted: bool = False


class ScanResult(BaseModel):
    safe: bool = Field(description="Whether the text is safe")
    action: Action = Field(description="Recommended action")
    risk_score: float = Field(ge=0.0, le=1.0, description="Overall risk score")
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: str | None = Field(default=None)
    latency_ms: float = Field(description="Total scan time in milliseconds")
    stages_run: list[str] = Field(default_factory=list)
    approval: ApprovalRequest | None = Field(
        default=None,
        description="Populated when action=review for side-effect tools in tainted sessions",
    )


class ScanRequest(BaseModel):
    text: str = Field(description="Text to scan")
    source: Source = Field(default=Source.USER)
    scanners: list[str] | None = Field(default=None)
    redact: bool = Field(default=True)
    redaction_mode: RedactionMode | None = Field(
        default=None,
        description="Override default redaction style; ignored when redact=false",
    )
    session_id: str | None = Field(default=None, description="Client session for logging")
    agent_id: str | None = Field(default=None, description="Agent identifier")
    turn_id: int | None = Field(default=None, description="Turn index within session")
    document_id: str | None = Field(default=None, description="RAG chunk or document id")
    block_coverage_ratio: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override document BLOCK coverage threshold",
    )
    redact_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    review_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    block_threshold: float | None = Field(default=None, ge=0.0, le=1.0)


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(description="Texts to scan")


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    scanners_loaded: list[str]
    model_loaded: bool
