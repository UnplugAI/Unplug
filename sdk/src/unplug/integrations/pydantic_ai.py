"""Pydantic AI integration: validators and tool guards."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def pydantic_ai_input_validator(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Validate user prompt before ``Agent.run``; return redacted text or raise."""
    h = hooks or AgentHooks()

    def validate(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return validate


def pydantic_ai_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Wrap Pydantic AI tool calls."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def pydantic_ai_output_validator(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Validate model output before returning to the caller."""
    h = hooks or AgentHooks()

    def validate(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.result.redacted_text or text

    return validate
