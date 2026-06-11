"""Reusable Guard hooks for agent frameworks (LangGraph, Agno, custom loops)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.api.types import ScanResult
from unplug.models import ScanRequest


@dataclass
class HookDecision:
    """Outcome of a Guard hook — allow, block, or review."""

    allowed: bool
    result: ScanResult
    message: str | None = None

    @property
    def action(self) -> Action:
        return self.result.action


@dataclass
class AgentHooks:
    """Drop-in Guard hooks for any agent runtime.

    Wire these into LangGraph nodes, Agno ``pre_hooks`` / tool middleware,
    or a plain ReAct loop. Tool enforcement always runs locally.
    """

    guard: Guard = field(default_factory=Guard)

    def scan_user_input(self, text: str, *, source: Source | str = Source.USER) -> HookDecision:
        result = self.guard.scan(text, source=source)
        allowed = result.safe and result.action in (Action.ALLOW, Action.ABSTAIN)
        if allowed:
            msg = None
        else:
            msg = f"Input blocked: {result.action.value} (risk={result.risk_score:.2f})"
        return HookDecision(allowed=allowed, result=result, message=msg)

    def scan_agent_output(self, text: str) -> HookDecision:
        result = self.guard.scan_output(text)
        allowed = result.safe and result.action == Action.ALLOW
        msg = None if allowed else f"Output blocked: {result.action.value}"
        return HookDecision(allowed=allowed, result=result, message=msg)

    def wrap_retrieved_content(self, text: str) -> tuple[str, HookDecision]:
        wrapped = self.guard.wrap_for_context(text, source=Source.RETRIEVED)
        result = self.guard.scan(wrapped, source=Source.RETRIEVED)
        allowed = result.action not in (Action.BLOCK,)
        self.guard.notify_taint_source("web_fetch")
        msg = None if allowed else "Retrieved content blocked"
        return wrapped, HookDecision(allowed=allowed, result=result, message=msg)

    def before_tool_call(self, name: str, args: dict[str, Any]) -> HookDecision:
        result = self.guard.check_tool_call(name, args)
        allowed = result.action == Action.ALLOW and result.safe
        msg = None
        if not allowed and result.findings:
            msg = result.findings[0].evidence
        return HookDecision(allowed=allowed, result=result, message=msg)

    def scan_request_isolated(self, text: str, *, source: Source | str = Source.USER) -> ScanResult:
        """Stateless scan — use in eval harnesses to avoid session bleed."""
        req = ScanRequest(text=text, source=source)
        return self.guard.scan_request(req, isolated=True)

    def reset_session(self) -> None:
        self.guard.reset_session_taint()
