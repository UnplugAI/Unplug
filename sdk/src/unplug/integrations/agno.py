"""Agno integration — Guard hooks for Agno Agent pre/post hooks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def agno_pre_run_hook(hooks: AgentHooks | None = None) -> Callable[..., None]:
    """Agno-style pre-run hook: scans the user prompt before the agent executes.

    Usage with Agno Agent::

        from agno.agent import Agent
        from unplug.integrations.agno import agno_pre_run_hook, AgentHooks

        hooks = AgentHooks(Guard())
        agent = Agent(pre_hooks=[agno_pre_run_hook(hooks)])

    The hook accepts ``(agent, user_message, **kwargs)`` or ``(user_message,)`` depending
    on Agno version — we read the first string argument.
    """
    h = hooks or AgentHooks()

    def hook(*args: Any, **kwargs: Any) -> None:
        del kwargs
        user_text = ""
        for arg in args:
            if isinstance(arg, str) and arg.strip():
                user_text = arg
                break
        if not user_text and args:
            last = args[-1]
            if hasattr(last, "get"):
                user_text = str(last.get("message") or last.get("content") or "")
        decision = h.scan_user_input(user_text)
        require_allowed(decision)

    return hook


def agno_tool_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Wrap tool execution: call before ``agent.run_tool`` or in Agno tool middleware."""
    h = hooks or AgentHooks()

    def wrapper(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return wrapper


def agno_post_run_hook(hooks: AgentHooks | None = None) -> Callable[[str], str]:
    """Scan agent output; return redacted text or raise if blocked."""
    h = hooks or AgentHooks()

    def hook(response: str) -> str:
        decision = h.scan_agent_output(response)
        require_allowed(decision)
        if decision.result.redacted_text is not None:
            return decision.result.redacted_text
        return response

    return hook
