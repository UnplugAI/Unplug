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

from unplug.integrations.hooks import AgentHooks, HookDecision, flatten_text
from unplug.integrations.langgraph import require_allowed


def _scan_redact_content(content: Any, scan: Callable[[str], HookDecision]) -> Any:
    """Scan ``str`` or multimodal-``list`` message content, redacting in place.

    AG2's ``process_last_received_message`` hook receives the *content* of the
    last message — a plain ``str`` or a list of multimodal blocks
    (``{"type": "text", "text": ...}`` plus image/file blocks), not the message
    history. We scan each text payload and write redactions back into the same
    shape so non-text blocks (images) are preserved rather than flattened into a
    string. Returns the original object unchanged when nothing was redacted (so
    AG2's "did a hook modify this?" identity check stays correct). Raises when
    Unplug blocks the content.
    """
    if isinstance(content, list):
        new_blocks: list[Any] = []
        changed = False
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                decision = scan(block["text"])
                require_allowed(decision)
                new_block = dict(block)
                if decision.redacted_text and decision.redacted_text != block["text"]:
                    new_block["text"] = decision.redacted_text
                    changed = True
                new_blocks.append(new_block)
            else:
                new_blocks.append(block)
        return new_blocks if changed else content

    text = content if isinstance(content, str) else flatten_text(content)
    decision = scan(text)
    require_allowed(decision)
    redacted = decision.redacted_text
    if isinstance(content, str) and redacted and redacted != text:
        return redacted
    return content


def ag2_received_message_hook(
    hooks: AgentHooks | None = None,
) -> Callable[[Any], Any]:
    """Build a ``process_last_received_message`` hook: scan incoming content."""
    h = hooks or AgentHooks()

    def hook(content: Any) -> Any:
        return _scan_redact_content(content, h.scan_user_input)

    return hook


def ag2_message_hook(
    hooks: AgentHooks | None = None,
) -> Callable[..., Any]:
    """Build a ``process_message_before_send`` hook: scan outgoing messages.

    Signature matches AG2: ``(sender, message, recipient, silent) -> message``.
    Raises when Unplug blocks the message; otherwise redacts the ``content``
    (preserving multimodal list structure).
    """
    h = hooks or AgentHooks()

    def hook(sender: Any, message: Any, recipient: Any, silent: Any) -> Any:
        if isinstance(message, dict):
            original = message.get("content", "")
            new_content = _scan_redact_content(original, h.scan_agent_output)
            if new_content is not original:
                message["content"] = new_content
            return message
        return _scan_redact_content(message, h.scan_agent_output)

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
