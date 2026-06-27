"""Strands Agents integration: a HookProvider that cancels unsafe tool calls.

`Strands Agents <https://strandsagents.com/>`_ exposes a strongly-typed hooks
system. Unplug ships a ``HookProvider`` that subscribes to the before-tool event
and **cancels** a destructive/exfil tool call (``event.cancel_tool = reason``)
before it runs — the documented way to gate tools. Input/output text guards are
provided for the turn boundaries.

The provider is duck-typed: it reads ``event.tool_use`` and sets
``event.cancel_tool`` without importing Strands, so its logic unit-tests without
Strands installed. Only ``register_hooks`` lazy-imports ``strands`` (to resolve
the event class, whose name changed from ``BeforeToolInvocationEvent`` to
``BeforeToolCallEvent`` across releases — both are handled).

Install the optional extra::

    pip install "unplug-ai[strands]"

Usage::

    from strands import Agent
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.strands import UnplugHookProvider

    hooks = AgentHooks(Guard())
    agent = Agent(model=model, tools=[...], hooks=[UnplugHookProvider(hooks)])
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def strands_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan a user prompt before ``agent(prompt)``; return redacted text or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def strands_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan an agent's final text before returning it; return redacted or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def strands_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate: ``decision = guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def _tool_use_name_args(tool_use: Any) -> tuple[str, dict[str, Any]]:
    """Pull ``(name, args)`` from a Strands ``tool_use`` (dict or object)."""
    if isinstance(tool_use, dict):
        name = tool_use.get("name") or "tool"
        raw_args = tool_use.get("input") or tool_use.get("arguments") or {}
    else:
        name = getattr(tool_use, "name", None) or "tool"
        raw_args = getattr(tool_use, "input", None) or {}
    args = dict(raw_args) if isinstance(raw_args, dict) else {"input": raw_args}
    return str(name), args


def _resolve_before_tool_event() -> type:
    try:
        from strands import hooks as strands_hooks
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "Strands integration requires the extra: pip install unplug-ai[strands]"
        raise ImportError(msg) from exc
    for attr in ("BeforeToolCallEvent", "BeforeToolInvocationEvent"):
        event = getattr(strands_hooks, attr, None)
        if event is not None:
            return event
    msg = "strands.hooks exposes no BeforeTool*Event; upgrade strands-agents"
    raise ImportError(msg)


class UnplugHookProvider:
    """Strands ``HookProvider`` that cancels destructive/exfil tool calls.

    Implements the ``HookProvider`` protocol structurally (``register_hooks``);
    no Strands base class is needed. The before-tool callback is duck-typed.
    """

    def __init__(self, hooks: AgentHooks | None = None) -> None:
        self._hooks = hooks or AgentHooks()

    def register_hooks(self, registry: Any, **kwargs: Any) -> None:
        registry.add_callback(_resolve_before_tool_event(), self.on_before_tool_call)

    def on_before_tool_call(self, event: Any) -> None:
        name, args = _tool_use_name_args(getattr(event, "tool_use", None))
        decision = self._hooks.before_tool_call(name, args)
        if not decision.allowed:
            event.cancel_tool = decision.message or "Tool call blocked by Unplug."


def unplug_hook_provider(hooks: AgentHooks | None = None) -> UnplugHookProvider:
    """Convenience builder for ``Agent(hooks=[unplug_hook_provider(hooks)])``."""
    return UnplugHookProvider(hooks)
