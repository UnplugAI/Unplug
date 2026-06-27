"""Atomic Agents integration: guard schema-typed agent I/O and tools.

`Atomic Agents <https://brainblend-ai.github.io/atomic-agents/>`_ (v2) is a
Pydantic-schema-driven framework: ``AtomicAgent[InputSchema, OutputSchema]`` with
``agent.run(input_schema) -> output_schema``, where schemas subclass
``BaseIOSchema`` (default text field ``chat_message``). Unplug wires in at:

- **Input** — scan the input schema's text field before ``agent.run`` (redact or raise).
- **Output** — scan the output schema's text field after ``agent.run``.
- **Tools** — gate ``BaseTool`` calls before they execute.

Schemas are duck-typed by field name, so this module imports and unit-tests
without Atomic Agents installed. (Atomic Agents 2.x requires Python >=3.12, so the
extra is a no-op on 3.11.)

Install the optional extra::

    pip install "unplug-ai[atomic-agents]"

Usage::

    from atomic_agents import AtomicAgent, BasicChatInputSchema, BasicChatOutputSchema
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.atomic_agents import atomic_input_guard, atomic_scan_output

    hooks = AgentHooks(Guard())
    guard_in = atomic_input_guard(hooks)

    safe_input = guard_in(BasicChatInputSchema(chat_message=user_text))  # redacts or raises
    response = agent.run(safe_input)
    atomic_scan_output(hooks, response)  # raises on leak / unsafe output
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed

_DEFAULT_FIELD = "chat_message"


def atomic_extract_text(schema: Any, *, field: str = _DEFAULT_FIELD) -> str:
    """Pull the text out of an Atomic Agents IO schema (or any object/str)."""
    if isinstance(schema, str):
        return schema
    value = getattr(schema, field, None)
    if isinstance(value, str):
        return value
    dump = getattr(schema, "model_dump", None)
    if callable(dump):
        for item in dump().values():
            if isinstance(item, str):
                return item
    return str(value) if value is not None else ""


def _redact_field(schema: Any, field: str, redacted: str) -> Any:
    if isinstance(schema, str):
        return redacted
    try:
        setattr(schema, field, redacted)
    except (AttributeError, ValueError, TypeError):
        copy = getattr(schema, "model_copy", None)
        if callable(copy):
            return copy(update={field: redacted})
    return schema


def atomic_scan_input(
    hooks: AgentHooks | None,
    schema: Any,
    *,
    field: str = _DEFAULT_FIELD,
) -> Any:
    """Scan an input schema's text; redact the field or raise, return the schema."""
    h = hooks or AgentHooks()
    text = atomic_extract_text(schema, field=field)
    decision = h.scan_user_input(text)
    require_allowed(decision)
    if decision.redacted_text and decision.redacted_text != text:
        return _redact_field(schema, field, decision.redacted_text)
    return schema


def atomic_scan_output(
    hooks: AgentHooks | None,
    schema: Any,
    *,
    field: str = _DEFAULT_FIELD,
) -> Any:
    """Scan an output schema's text; redact the field or raise, return the schema."""
    h = hooks or AgentHooks()
    text = atomic_extract_text(schema, field=field)
    decision = h.scan_agent_output(text)
    require_allowed(decision)
    if decision.redacted_text and decision.redacted_text != text:
        return _redact_field(schema, field, decision.redacted_text)
    return schema


def atomic_input_guard(
    hooks: AgentHooks | None = None,
    *,
    field: str = _DEFAULT_FIELD,
) -> Callable[[Any], Any]:
    """Build a callable that scans an input schema before ``agent.run``."""
    h = hooks or AgentHooks()

    def guard(schema: Any) -> Any:
        return atomic_scan_input(h, schema, field=field)

    return guard


def atomic_output_guard(
    hooks: AgentHooks | None = None,
    *,
    field: str = _DEFAULT_FIELD,
) -> Callable[[Any], Any]:
    """Build a callable that scans an output schema after ``agent.run``."""
    h = hooks or AgentHooks()

    def guard(schema: Any) -> Any:
        return atomic_scan_output(h, schema, field=field)

    return guard


def atomic_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate for a Atomic Agents ``BaseTool``: ``guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard
