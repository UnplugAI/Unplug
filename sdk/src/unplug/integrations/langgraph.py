"""LangGraph integration — Guard hooks as node wrappers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug import Guard
from unplug.integrations.hooks import AgentHooks, HookDecision


def require_allowed(decision: HookDecision) -> None:
    if not decision.allowed:
        msg = decision.message or "Unplug blocked this step"
        raise RuntimeError(msg)


def langgraph_input_node(
    hooks: AgentHooks | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Return a LangGraph node that scans the latest user message before the agent runs.

    Expects state with ``messages`` (list of dicts with ``role`` and ``content``).
    Adds ``unplug_input_decision`` to state; raises if blocked.

    Usage::

        from unplug.integrations.langgraph import langgraph_input_node, AgentHooks
        hooks = AgentHooks(Guard())
        graph.add_node("unplug_input", langgraph_input_node(hooks))
    """
    h = hooks or AgentHooks()

    def node(state: dict[str, Any]) -> dict[str, Any]:
        messages = state.get("messages") or []
        user_text = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                user_text = str(msg.get("content", ""))
                break
        decision = h.scan_user_input(user_text)
        require_allowed(decision)
        return {**state, "unplug_input_decision": decision.result.model_dump(mode="json")}

    return node


def langgraph_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool hook: ``decision = langgraph_tool_guard(hooks)(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard_tool(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard_tool


def guard_from_env(**guard_kwargs: Any) -> AgentHooks:
    """Build hooks from Guard kwargs (``mode='server'`` for hosted API)."""
    return AgentHooks(Guard(**guard_kwargs))
