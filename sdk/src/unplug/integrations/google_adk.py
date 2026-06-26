"""Google ADK integration: Unplug as before-model / before-tool guardrails.

The `Agent Development Kit <https://google.github.io/adk-docs/>`_ exposes
guardrail hooks that can short-circuit a step by *returning an object*:

- ``before_model_callback(callback_context, llm_request) -> Optional[LlmResponse]``
  Return an ``LlmResponse`` to skip the LLM call (input guardrail).
- ``before_tool_callback(tool, args, tool_context) -> Optional[dict]``
  Return a ``dict`` to skip the tool and use it as the result (tool policy).

ADK passes callback arguments **by keyword**, so the parameter names below must
stay exactly ``callback_context`` / ``llm_request`` / ``tool`` / ``args`` /
``tool_context``.

The request parsing (``adk_extract_user_text``) and the tool callback are plain
and duck-typed, so they are testable without ADK installed. Only
``unplug_before_model_callback`` lazy-imports ADK (to build the ``LlmResponse``).

Install the optional extra::

    pip install "unplug-ai[google-adk]"

Usage::

    from google.adk.agents import LlmAgent
    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.google_adk import (
        unplug_before_model_callback,
        unplug_before_tool_callback,
    )

    hooks = AgentHooks(Guard())
    agent = LlmAgent(
        name="assistant",
        model="gemini-2.0-flash",
        before_model_callback=unplug_before_model_callback(hooks),
        before_tool_callback=unplug_before_tool_callback(hooks),
    )
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision

_BLOCKED_MODEL_REPLY = "Request blocked by Unplug: the input failed a safety guardrail."


def adk_extract_user_text(llm_request: Any) -> str:
    """Pull the latest user text out of an ADK ``LlmRequest`` (duck-typed).

    Reads ``llm_request.contents`` (a list of ``types.Content``), preferring the
    last ``role == "user"`` turn and joining its parts' ``.text``. Falls back to
    the final content if no user role is tagged. Returns ``""`` when empty.
    """
    contents = getattr(llm_request, "contents", None) or []

    def _join_parts(content: Any) -> str:
        parts = getattr(content, "parts", None) or []
        texts = [getattr(p, "text", None) for p in parts]
        return "\n".join(t for t in texts if t)

    for content in reversed(contents):
        if getattr(content, "role", None) == "user":
            text = _join_parts(content)
            if text:
                return text
    if contents:
        return _join_parts(contents[-1])
    return ""


def adk_scan_request(hooks: AgentHooks, llm_request: Any) -> HookDecision:
    """Scan the user text carried by an ADK ``LlmRequest``."""
    return hooks.scan_user_input(adk_extract_user_text(llm_request))


def unplug_before_tool_callback(
    hooks: AgentHooks | None = None,
) -> Callable[..., dict[str, Any] | None]:
    """Build a ``before_tool_callback``: block destructive/exfil tool calls.

    Returns a callback returning ``None`` to allow the tool, or a result ``dict``
    (which ADK uses in place of the tool's output) to block it. Tool policy is
    always enforced locally, so this needs no ADK import.
    """
    h = hooks or AgentHooks()

    def before_tool_callback(
        tool: Any,
        args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any] | None:
        name = getattr(tool, "name", None) or str(tool)
        decision = h.before_tool_call(name, dict(args or {}))
        if decision.allowed:
            return None
        return {
            "status": "blocked",
            "error": decision.message or "Tool call blocked by Unplug.",
            "blocked_by": "unplug",
        }

    return before_tool_callback


def _require_adk() -> tuple[Any, Any]:
    try:
        from google.adk.models import LlmResponse
        from google.genai import types
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "Google ADK integration requires the extra: pip install unplug-ai[google-adk]"
        raise ImportError(msg) from exc
    return LlmResponse, types


def unplug_before_model_callback(
    hooks: AgentHooks | None = None,
    *,
    blocked_reply: str = _BLOCKED_MODEL_REPLY,
) -> Callable[..., Any | None]:
    """Build a ``before_model_callback`` that gates the user turn.

    Returns a callback returning ``None`` to let the LLM run, or an
    ``LlmResponse`` (which ADK serves in place of the model output) when the
    user input is blocked — the model is never called for unsafe input.
    """
    h = hooks or AgentHooks()

    def before_model_callback(callback_context: Any, llm_request: Any) -> Any | None:
        decision = adk_scan_request(h, llm_request)
        if decision.allowed:
            return None
        llm_response_cls, types = _require_adk()
        message = decision.message or blocked_reply
        return llm_response_cls(
            content=types.Content(role="model", parts=[types.Part(text=message)]),
        )

    return before_model_callback
