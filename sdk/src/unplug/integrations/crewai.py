"""CrewAI integration: Guard hooks for task input, tools, and crew output."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def crewai_task_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], None]:
    """Scan the task prompt before ``Crew.kickoff`` or an agent step.

    Usage::

        from crewai import Crew
        from unplug.integrations.crewai import crewai_task_input_guard, AgentHooks

        guard_input = crewai_task_input_guard(AgentHooks(Guard()))
        guard_input(inputs["topic"])  # call before kickoff
    """
    h = hooks or AgentHooks()

    def guard(text: str) -> None:
        decision = h.scan_user_input(text)
        require_allowed(decision)

    return guard


def crewai_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool hook for CrewAI tool execution."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def crewai_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan final crew output; return redacted text or raise if blocked."""
    h = hooks or AgentHooks()

    def guard(output: str) -> str:
        decision = h.scan_agent_output(output)
        require_allowed(decision)
        return decision.result.redacted_text or output

    return guard
