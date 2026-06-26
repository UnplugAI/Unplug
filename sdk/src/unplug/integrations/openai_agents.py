"""OpenAI Agents SDK integration: Unplug as input/output guardrails.

The `OpenAI Agents SDK <https://openai.github.io/openai-agents-python/>`_ has a
native guardrails system: an input/output guardrail is a function returning a
``GuardrailFunctionOutput`` whose ``tripwire_triggered`` flag, when ``True``,
halts the run with an ``{Input,Output}GuardrailTripwireTriggered`` exception.
Unplug slots straight into that contract.

The decision core (``evaluate_input`` / ``evaluate_output``) is plain and has no
``agents`` dependency, so it is fully testable without the SDK installed. The
``openai_agents_input_guardrail`` / ``openai_agents_output_guardrail`` factories
lazy-import ``agents`` and only build the native guardrail when you call them.
Tool enforcement (``openai_agents_tool_guard``) is local and SDK-free.

Install the optional extra::

    pip install "unplug-ai[openai-agents]"

Usage::

    from agents import Agent
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.openai_agents import (
        openai_agents_input_guardrail,
        openai_agents_output_guardrail,
    )

    hooks = AgentHooks(Guard())
    agent = Agent(
        name="Assistant",
        instructions="You are a helpful assistant.",
        input_guardrails=[openai_agents_input_guardrail(hooks)],
        output_guardrails=[openai_agents_output_guardrail(hooks)],
    )
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision


@dataclass
class GuardEvaluation:
    """SDK-agnostic guardrail decision: should the tripwire fire?"""

    tripwire_triggered: bool
    decision: HookDecision

    @property
    def output_info(self) -> dict[str, Any]:
        result = self.decision.result
        return {
            "action": result.action.value,
            "risk_score": round(result.risk_score, 4),
            "message": self.decision.message,
            "categories": sorted({f.category for f in result.findings}),
        }


def _coerce_input_text(value: Any) -> str:
    """Flatten the Agents SDK input (``str`` or a list of input items) to text."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                content = item.get("content")
            else:
                content = getattr(item, "content", None)
            if isinstance(content, str):
                parts.append(content)
            elif content is not None:
                parts.append(str(content))
            elif not isinstance(item, dict):
                parts.append(str(item))
        return "\n".join(p for p in parts if p)
    return str(value)


def _coerce_output_text(value: Any) -> str:
    """Flatten an agent output (``str``, message object, or model) to text."""
    if isinstance(value, str):
        return value
    for attr in ("response", "content", "text", "output", "final_output"):
        inner = getattr(value, attr, None)
        if isinstance(inner, str):
            return inner
    return str(value)


def evaluate_input(hooks: AgentHooks, text: str) -> GuardEvaluation:
    """Scan user input; trip the wire when Unplug would not ALLOW it."""
    decision = hooks.scan_user_input(text)
    return GuardEvaluation(tripwire_triggered=not decision.allowed, decision=decision)


def evaluate_output(hooks: AgentHooks, text: str) -> GuardEvaluation:
    """Scan agent output; trip the wire on secret leaks / unsafe content."""
    decision = hooks.scan_agent_output(text)
    return GuardEvaluation(tripwire_triggered=not decision.allowed, decision=decision)


def openai_agents_tool_guard(
    hooks: AgentHooks | None = None,
) -> Any:
    """Local tool gate: ``decision = guard(tool_name, tool_args)``.

    Tool policy is always enforced locally and never delegated to the model,
    so this needs no ``agents`` import. Wrap your tool's body with it::

        guard = openai_agents_tool_guard(hooks)
        if not guard("shell", {"command": cmd}).allowed:
            raise RuntimeError("blocked")
    """
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def _require_agents() -> Any:
    try:
        import agents
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "OpenAI Agents integration requires the extra: pip install unplug-ai[openai-agents]"
        raise ImportError(msg) from exc
    return agents


def openai_agents_input_guardrail(
    hooks: AgentHooks | None = None,
    *,
    name: str = "unplug_input",
) -> Any:
    """Build a native input guardrail for ``Agent(input_guardrails=[...])``.

    Returns an ``InputGuardrail`` that trips when Unplug blocks the user turn,
    raising ``InputGuardrailTripwireTriggered`` and halting the run.
    """
    h = hooks or AgentHooks()
    agents = _require_agents()

    def guardrail(context: Any, agent: Any, agent_input: Any) -> Any:
        evaluation = evaluate_input(h, _coerce_input_text(agent_input))
        return agents.GuardrailFunctionOutput(
            output_info=evaluation.output_info,
            tripwire_triggered=evaluation.tripwire_triggered,
        )

    return agents.input_guardrail(name=name)(guardrail)


def openai_agents_output_guardrail(
    hooks: AgentHooks | None = None,
    *,
    name: str = "unplug_output",
) -> Any:
    """Build a native output guardrail for ``Agent(output_guardrails=[...])``.

    Returns an ``OutputGuardrail`` that trips when the agent's final output
    leaks secrets or carries unsafe content.
    """
    h = hooks or AgentHooks()
    agents = _require_agents()

    def guardrail(context: Any, agent: Any, agent_output: Any) -> Any:
        evaluation = evaluate_output(h, _coerce_output_text(agent_output))
        return agents.GuardrailFunctionOutput(
            output_info=evaluation.output_info,
            tripwire_triggered=evaluation.tripwire_triggered,
        )

    return agents.output_guardrail(name=name)(guardrail)
