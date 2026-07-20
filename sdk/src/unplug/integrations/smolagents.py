"""smolagents integration: task gate, final-answer checks, and tool policy.

`smolagents <https://huggingface.co/docs/smolagents>`_ runs code/tool-calling
agents. Unplug wires into three points:

- **Task gate** — scan the task string before ``agent.run(task)``.
- **Final-answer check** — ``final_answer_checks=[...]`` runs validators with the
  signature ``(final_answer, memory, agent) -> bool`` before an answer is
  accepted; Unplug raises on secret leaks / unsafe output.
- **Tool policy** — gate destructive/exfil tool calls locally.

All three are plain callables with no smolagents dependency, so they import and
unit-test without smolagents installed.

Install the optional extra::

    pip install "unplug-ai[smolagents]"

Usage::

    from smolagents import CodeAgent
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.smolagents import (
        smolagents_final_answer_check,
        smolagents_task_guard,
    )

    hooks = AgentHooks(Guard())
    guard_task = smolagents_task_guard(hooks)
    agent = CodeAgent(
        tools=[],
        model=model,
        final_answer_checks=[smolagents_final_answer_check(hooks)],
    )
    agent.run(guard_task("Summarize the latest sales report"))
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision, flatten_text
from unplug.integrations.langgraph import require_allowed


def _coerce_text(value: Any) -> str:
    # Flatten structured answers (dict / model / tool result) rather than trusting
    # ``.text`` or ``str(value)`` alone, so a secret hidden in a sibling field is
    # still scanned instead of being represented by a harmless string form.
    if isinstance(value, str):
        return value
    return flatten_text(value)


def smolagents_task_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan the task before ``agent.run``; return redacted text or raise."""
    h = hooks or AgentHooks()

    def guard(task: str) -> str:
        decision = h.scan_user_input(task)
        require_allowed(decision)
        return decision.redacted_text or task

    return guard


def smolagents_final_answer_check(
    hooks: AgentHooks | None = None,
) -> Callable[..., bool]:
    """Build a ``final_answer_checks`` validator: ``(final_answer, memory, agent)``.

    Returns ``True`` when the final answer is safe; raises ``RuntimeError`` when
    Unplug blocks it (secret leak, unsafe content), stopping the agent before the
    answer is surfaced. smolagents accepts both ``bool`` returns and raised
    errors as a failed check.
    """
    h = hooks or AgentHooks()

    def check(final_answer: Any, memory: Any = None, agent: Any = None) -> bool:
        decision = h.scan_agent_output(_coerce_text(final_answer))
        require_allowed(decision)
        return True

    return check


def smolagents_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate for a smolagents tool: ``guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard
