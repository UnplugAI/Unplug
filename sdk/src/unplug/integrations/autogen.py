"""Microsoft AutoGen integration: Guard hooks for chat messages and tool calls."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def autogen_user_message_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Filter inbound user messages before they reach the agent group.

    Expects an AutoGen-style message dict with a ``content`` field.
    Returns the message unchanged when allowed; raises when blocked.
    """
    h = hooks or AgentHooks()

    def hook(message: dict[str, Any]) -> dict[str, Any]:
        text = str(message.get("content") or message.get("message") or "")
        decision = h.scan_user_input(text)
        require_allowed(decision)
        if decision.redacted_text is not None:
            return {**message, "content": decision.redacted_text}
        return message

    return hook


def autogen_tool_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool hook for ``register_function`` / tool middleware."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def autogen_reply_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan agent reply text before it is sent to the user or another agent."""
    h = hooks or AgentHooks()

    def hook(reply: str) -> str:
        decision = h.scan_agent_output(reply)
        require_allowed(decision)
        return decision.result.redacted_text or reply

    return hook
