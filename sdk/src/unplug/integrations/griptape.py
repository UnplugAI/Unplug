"""Griptape integration: guard task I/O via run hooks and gate tool activities.

`Griptape <https://griptape.ai/>`_ structures (Agent, Pipeline, Workflow) run
Tasks; every Task implements ``on_before_run`` / ``on_after_run`` lifecycle hooks,
and Tools are ``BaseTool`` classes with ``@activity`` methods. Unplug wires in at:

- **Input** — ``unplug_before_run`` scans ``task.input.value`` before the task runs
  (redacts in place or raises), the documented pattern for masking task input.
- **Output** — ``unplug_after_run`` scans ``task.output.value`` after the task runs.
- **Tools** — ``griptape_tool_guard`` gates a tool activity before it executes.

The run hooks are duck-typed (they read ``task.input.value`` / ``task.output.value``)
and every guard is a plain callable, so this module imports and unit-tests without
Griptape installed.

Install the optional extra::

    pip install "unplug-ai[griptape]"

Usage::

    from griptape.structures import Agent
    from griptape.tasks import PromptTask
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.griptape import unplug_before_run, unplug_after_run

    hooks = AgentHooks(Guard())
    agent = Agent(
        tasks=[
            PromptTask(
                "Respond to this user: {{ args[0] }}",
                on_before_run=unplug_before_run(hooks),
                on_after_run=unplug_after_run(hooks),
            )
        ]
    )
    agent.run("Summarize the latest sales report")
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def griptape_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan task input text before ``agent.run``; return redacted text or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def griptape_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan an agent's output text before returning it; return redacted or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def griptape_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-activity gate for a Griptape tool: ``guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def unplug_before_run(
    hooks: AgentHooks | None = None,
) -> Callable[[Any], None]:
    """Build an ``on_before_run(task)`` hook that scans the task's input.

    Reads ``task.input.value``; raises ``RuntimeError`` when Unplug blocks it,
    otherwise replaces ``task.input`` with the redacted text (Griptape coerces a
    string back into a ``TextArtifact``).
    """
    h = hooks or AgentHooks()

    def on_before_run(task: Any) -> None:
        text = getattr(getattr(task, "input", None), "value", None)
        if not isinstance(text, str):
            return
        decision = h.scan_user_input(text)
        require_allowed(decision)
        if decision.redacted_text and decision.redacted_text != text:
            task.input = decision.redacted_text

    return on_before_run


def unplug_after_run(
    hooks: AgentHooks | None = None,
) -> Callable[[Any], None]:
    """Build an ``on_after_run(task)`` hook that scans the task's output.

    Reads ``task.output.value``; raises ``RuntimeError`` when Unplug blocks the
    output, otherwise rewrites ``task.output.value`` with the redacted text.
    """
    h = hooks or AgentHooks()

    def on_after_run(task: Any) -> None:
        output = getattr(task, "output", None)
        text = getattr(output, "value", None)
        if not isinstance(text, str):
            return
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        if decision.redacted_text and decision.redacted_text != text:
            output.value = decision.redacted_text

    return on_after_run
