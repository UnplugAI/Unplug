"""AG2 integration: guard ConversableAgent messages and tools via hooks.

`AG2 <https://docs.ag2.ai/>`_ (the community fork of AutoGen, imported as
``autogen``) lets you attach hooks to a ``ConversableAgent`` with
``register_hook``. Unplug wires in at:

- **Incoming** — ``process_last_received_message`` scans the last received message
  for injection (redacts or raises).
- **Outgoing** — ``process_message_before_send`` scans a message before it is sent
  to another agent, catching leaked secrets / unsafe content.
- **Tools** — ``ag2_guard_tool`` wraps a callable so a destructive call is blocked
  before it executes; pair it with ``register_function``.

.. note::
   This is distinct from the ``autogen`` extra, which targets Microsoft's
   ``autogen-agentchat`` (imported as ``autogen_agentchat``). AG2 installs as the
   ``ag2`` package and imports as ``autogen``.

Every hook is duck-typed (message dicts / strings) and registered by string name,
so this module imports and unit-tests without AG2 installed.

Install the optional extra::

    pip install "unplug-ai[ag2]"

Usage::

    from autogen import ConversableAgent
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.ag2 import register_unplug_hooks

    hooks = AgentHooks(Guard())
    agent = ConversableAgent(name="assistant", llm_config=llm_config)
    register_unplug_hooks(agent, hooks)
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def ag2_received_message_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[Any], Any]:
    """Build a ``process_last_received_message`` hook: scan incoming content."""
    h = hooks or AgentHooks()

    def hook(content: Any) -> Any:
        text = content if isinstance(content, str) else str(content)
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or content

    return hook


def ag2_message_hook(
    hooks: AgentHooks | None = None,
) -> Callable[..., Any]:
    """Build a ``process_message_before_send`` hook: scan outgoing messages.

    Signature matches AG2: ``(sender, message, recipient, silent) -> message``.
    Raises when Unplug blocks the message; otherwise redacts the ``content``.
    """
    h = hooks or AgentHooks()

    def hook(sender: Any, message: Any, recipient: Any, silent: Any) -> Any:
        if isinstance(message, dict):
            text = str(message.get("content", ""))
        else:
            text = str(message)
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        redacted = decision.redacted_text
        if redacted and redacted != text:
            if isinstance(message, dict):
                message["content"] = redacted
            else:
                return redacted
        return message

    return hook


def ag2_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate: ``decision = guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def ag2_guard_tool(
    fn: Callable[..., Any],
    hooks: AgentHooks | None = None,
    *,
    name: str | None = None,
) -> Callable[..., Any]:
    """Wrap a tool callable so a blocked call raises before it runs.

    Preserves the wrapped function's signature/docstring so it stays usable with
    ``register_function`` / ``register_for_execution``.
    """
    h = hooks or AgentHooks()
    tool_name = name or getattr(fn, "__name__", "tool")

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        payload = dict(kwargs)
        if args:
            payload["args"] = list(args)
        require_allowed(h.before_tool_call(tool_name, payload))
        return fn(*args, **kwargs)

    return wrapper


def register_unplug_hooks(
    agent: Any,
    hooks: AgentHooks | None = None,
) -> None:
    """Register the incoming + outgoing Unplug hooks on a ``ConversableAgent``."""
    h = hooks or AgentHooks()
    agent.register_hook("process_last_received_message", ag2_received_message_hook(h))
    agent.register_hook("process_message_before_send", ag2_message_hook(h))
