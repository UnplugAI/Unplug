"""Human approval protocol for tainted side-effect tool calls."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from unplug.api.types import ApprovalRequest, Finding
from unplug.models import Action


def build_approval_request(
    *,
    tool_name: str,
    arguments: dict,
    findings: list[Finding],
    risk_score: float,
    action: Action,
    session_tainted: bool,
    reason: str | None = None,
) -> ApprovalRequest:
    summary = [f"{f.category}/{f.subcategory}: {f.evidence}" for f in findings[:8]]
    default_reason = reason or (
        "Side-effect tool call in tainted session requires operator approval"
        if session_tainted
        else "Tool call requires operator approval"
    )
    return ApprovalRequest(
        tool_name=tool_name,
        arguments=arguments,
        reason=default_reason,
        risk_score=risk_score,
        action=action,
        findings=summary,
        session_tainted=session_tainted,
    )


@runtime_checkable
class ApprovalProvider(Protocol):
    """Host integration: approve or deny REVIEW tool calls."""

    def request_approval(self, request: ApprovalRequest) -> bool:
        """Return True if the operator approved the tool call."""
        ...


class NullApprovalProvider:
    """Default: never auto-approves; host must set ToolCall.approved=True explicitly."""

    def request_approval(self, request: ApprovalRequest) -> bool:
        _ = request
        return False
