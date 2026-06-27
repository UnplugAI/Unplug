"""Letta integration: guard messages to/from a stateful Letta agent.

`Letta <https://docs.letta.com/>`_ (formerly MemGPT) runs persistent, stateful
agents behind a server; you talk to them with the ``letta-client`` SDK via
``client.agents.messages.create(...)``. Because the agent runs server-side, Unplug
guards the **client boundary**:

- **Input** — scan the user message before ``messages.create`` (redact or raise).
- **Output** — pull assistant text out of ``response.messages`` (the entries with
  ``message_type == "assistant_message"``) and scan it.
- **Tools** — gate client-side tool calls before they run.

Every function here is a plain callable that duck-types Letta's response objects,
so they import and unit-test without ``letta-client`` installed.

Install the optional extra::

    pip install "unplug-ai[letta]"

Usage::

    from letta_client import Letta
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.letta import letta_input_guard, scan_letta_response

    client = Letta(environment="local")
    hooks = AgentHooks(Guard())
    guard_in = letta_input_guard(hooks)

    response = client.agents.messages.create(
        agent_id=agent.id,
        messages=[{"role": "user", "content": guard_in(user_text)}],
    )
    decision = scan_letta_response(hooks, response)
    if not decision.allowed:
        ...  # withhold the assistant message
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def letta_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan a user message before ``messages.create``; redacted text or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def letta_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan assistant text before surfacing it; redacted text or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def letta_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate for client-side Letta tools: ``guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def letta_extract_assistant_text(response: Any) -> str:
    """Join the ``assistant_message`` contents from a Letta message response.

    Accepts a response object with a ``messages`` attribute or a raw iterable of
    messages; each message is duck-typed for ``message_type`` / ``content``.
    """
    messages = getattr(response, "messages", None)
    if messages is None:
        messages = response if isinstance(response, (list, tuple)) else []
    parts: list[str] = []
    for msg in messages:
        if getattr(msg, "message_type", None) != "assistant_message":
            continue
        content = getattr(msg, "content", None)
        if isinstance(content, str):
            parts.append(content)
        elif content is not None:
            parts.append(str(content))
    return "\n".join(parts)


def scan_letta_response(
    hooks: AgentHooks | None,
    response: Any,
) -> HookDecision:
    """Extract assistant text from a Letta response and scan it for leaks/unsafe output."""
    h = hooks or AgentHooks()
    return h.scan_agent_output(letta_extract_assistant_text(response))
