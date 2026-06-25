"""Semantic Kernel integration: filters for prompts, tools, and responses."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def semantic_kernel_prompt_filter(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan user prompt before kernel invocation."""
    h = hooks or AgentHooks()

    def filter_prompt(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return filter_prompt


def semantic_kernel_function_filter(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-invoke filter for SK plugin functions / native tools."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def semantic_kernel_response_filter(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan kernel output before returning to the host application."""
    h = hooks or AgentHooks()

    def filter_response(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.result.redacted_text or text

    return filter_response
