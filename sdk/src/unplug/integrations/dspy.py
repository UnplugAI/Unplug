"""DSPy integration: guard module inputs/outputs and ReAct tools.

`DSPy <https://dspy.ai/>`_ programs are ``dspy.Module`` subclasses with a
``forward`` method; ``dspy.ReAct`` runs a tool-calling loop over plain callables.
Unplug wires in at three points:

- **Input/output** — scan a program's string inputs before it runs and its
  ``dspy.Prediction`` text after (``unplug_guard_module`` wraps any module).
- **Tools** — ``dspy_guard_tool`` wraps a callable so a destructive call is
  blocked before it executes, keeping the signature DSPy needs for ``dspy.ReAct``.

The guard callables (``dspy_input_guard`` / ``dspy_output_guard`` /
``dspy_tool_guard`` / ``dspy_guard_tool``) are plain functions with no DSPy
dependency, so they unit-test without DSPy installed. Only
``unplug_guard_module`` lazy-imports ``dspy`` (it subclasses ``dspy.Module``).

Install the optional extra::

    pip install "unplug-ai[dspy]"

Usage::

    import dspy
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.dspy import unplug_guard_module, dspy_guard_tool

    hooks = AgentHooks(Guard())
    program = dspy.ChainOfThought("question -> answer")
    guarded = unplug_guard_module(program, hooks)   # scans input + output
    react = dspy.ReAct("question -> answer", tools=[dspy_guard_tool(send_email, hooks)])
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def dspy_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan a program's input before ``module(question=...)``; redacted or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def dspy_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Scan a program's answer text before returning it; redacted or raise."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def dspy_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate: ``decision = guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def dspy_guard_tool(
    fn: Callable[..., Any],
    hooks: AgentHooks | None = None,
    *,
    name: str | None = None,
) -> Callable[..., Any]:
    """Wrap a callable so a blocked call raises before the tool runs.

    Preserves the wrapped function's signature/docstring (via ``functools.wraps``)
    so it stays usable in ``dspy.ReAct(tools=[...])``::

        react = dspy.ReAct("question -> answer", tools=[dspy_guard_tool(send_email, hooks)])
    """
    h = hooks or AgentHooks()
    tool_name = name or getattr(fn, "__name__", "tool")

    @functools.wraps(fn)
    def wrapper(**kwargs: Any) -> Any:
        require_allowed(h.before_tool_call(tool_name, dict(kwargs)))
        return fn(**kwargs)

    return wrapper


def dspy_prediction_text(prediction: Any) -> str:
    """Best-effort extraction of the answer text from a ``dspy.Prediction``."""
    for attr in ("answer", "output", "response", "text"):
        value = getattr(prediction, attr, None)
        if isinstance(value, str):
            return value
    return str(prediction)


def _require_dspy() -> Any:
    try:
        import dspy
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "DSPy integration requires the extra: pip install unplug-ai[dspy]"
        raise ImportError(msg) from exc
    return dspy


def unplug_guard_module(
    program: Any,
    hooks: AgentHooks | None = None,
    *,
    scan_output: bool = True,
) -> Any:
    """Wrap a ``dspy.Module`` so Unplug scans its string inputs and answer.

    Returns a ``dspy.Module`` that scans every string input (raising on block),
    runs the wrapped ``program``, then scans the prediction's text before
    returning it. Invoke it like any module: ``guarded(question=...)``.
    """
    h = hooks or AgentHooks()
    dspy = _require_dspy()

    class UnplugGuard(dspy.Module):  # type: ignore[misc, name-defined]
        def __init__(self) -> None:
            super().__init__()
            self.program = program

        def forward(self, **kwargs: Any) -> Any:
            for value in kwargs.values():
                if isinstance(value, str):
                    require_allowed(h.scan_user_input(value))
            prediction = self.program(**kwargs)
            if scan_output:
                text = dspy_prediction_text(prediction)
                if text:
                    require_allowed(h.scan_agent_output(text))
            return prediction

    return UnplugGuard()
