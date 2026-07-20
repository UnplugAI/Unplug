"""LangChain (core) integration: Runnable guards + a tool-gating callback.

LangChain callbacks are observer-only — they cannot change or block the value
flowing through a chain. So enforcement lives in ``RunnableLambda`` wrappers you
compose into an LCEL chain (``guard | prompt | llm | guard``), while the callback
handler is used for the one place a callback *can* intervene: raising inside
``on_tool_start`` aborts a destructive tool before it runs.

The guard callables (``langchain_input_guard`` / ``langchain_output_guard`` /
``langchain_tool_guard``) are plain functions with no LangChain dependency, so
they are unit-testable without LangChain installed. ``unplug_input_runnable`` /
``unplug_output_runnable`` / ``unplug_callback_handler`` lazy-import
``langchain_core`` and are only built when called.

Install the optional extra::

    pip install "unplug-ai[langchain]"

Usage (LCEL)::

    from unplug import Guard
    from unplug.integrations.hooks import AgentHooks
    from unplug.integrations.langchain import unplug_input_runnable, unplug_output_runnable

    hooks = AgentHooks(Guard())
    chain = unplug_input_runnable(hooks) | prompt | llm | unplug_output_runnable(hooks)
    chain.invoke("user message")  # raises if blocked; redacts in place otherwise
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from unplug.integrations.hooks import AgentHooks, HookDecision
from unplug.integrations.langgraph import require_allowed


def langchain_input_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Return a ``str -> str`` guard for the head of an LCEL chain.

    Returns redacted text when safe; raises ``RuntimeError`` when the turn is
    blocked. Drop it in directly or via ``unplug_input_runnable``.
    """
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_user_input(text)
        require_allowed(decision)
        return decision.redacted_text or text

    return guard


def langchain_output_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str], str]:
    """Return a ``str -> str`` guard for the tail of an LCEL chain."""
    h = hooks or AgentHooks()

    def guard(text: str) -> str:
        decision = h.scan_agent_output(text)
        require_allowed(decision)
        return decision.result.redacted_text or text

    return guard


def langchain_tool_guard(
    hooks: AgentHooks | None = None,
) -> Callable[[str, dict[str, Any]], HookDecision]:
    """Pre-tool gate for a LangChain/LCEL tool: ``guard(tool_name, tool_args)``."""
    h = hooks or AgentHooks()

    def guard(name: str, args: dict[str, Any]) -> HookDecision:
        return h.before_tool_call(name, args)

    return guard


def _tool_call_args(input_str: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Resolve the args dict to scan for an ``on_tool_start`` callback.

    Newer LangChain forwards the structured tool arguments as ``inputs``; prefer
    them so field-sensitive policy (``command`` / ``query`` / ``path`` / ``url``)
    evaluates the real arguments instead of a single flattened string. Fall back
    to the positional ``input_str`` when structured inputs are unavailable.
    """
    inputs = kwargs.get("inputs")
    return inputs if isinstance(inputs, dict) else {"input": input_str}


def _require_langchain_core() -> Any:
    try:
        import langchain_core
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "LangChain integration requires the extra: pip install unplug-ai[langchain]"
        raise ImportError(msg) from exc
    return langchain_core


def unplug_input_runnable(hooks: AgentHooks | None = None) -> Any:
    """Build a ``RunnableLambda`` that scans/redacts input inside an LCEL chain."""
    _require_langchain_core()
    from langchain_core.runnables import RunnableLambda

    return RunnableLambda(langchain_input_guard(hooks))


def unplug_output_runnable(hooks: AgentHooks | None = None) -> Any:
    """Build a ``RunnableLambda`` that scans/redacts output inside an LCEL chain."""
    _require_langchain_core()
    from langchain_core.runnables import RunnableLambda

    return RunnableLambda(langchain_output_guard(hooks))


_UnplugCallbackHandler: type | None = None


def _build_callback_handler_class() -> type:
    _require_langchain_core()
    from langchain_core.callbacks import BaseCallbackHandler

    class UnplugCallbackHandler(BaseCallbackHandler):
        """Abort destructive tools at ``on_tool_start`` (the one blocking hook).

        Callbacks otherwise observe only; this handler raises ``RuntimeError``
        before a blocked tool runs. Pair it with the Runnable guards for full
        input/output coverage.
        """

        def __init__(self, hooks: AgentHooks | None = None) -> None:
            self._hooks = hooks or AgentHooks()

        def on_tool_start(
            self,
            serialized: dict[str, Any],
            input_str: str,
            **kwargs: Any,
        ) -> None:
            name = (serialized or {}).get("name", "tool")
            decision = self._hooks.before_tool_call(name, _tool_call_args(input_str, kwargs))
            require_allowed(decision)

    return UnplugCallbackHandler


def unplug_callback_handler(hooks: AgentHooks | None = None) -> Any:
    """Return an ``UnplugCallbackHandler`` instance for ``config={"callbacks": [...]}``."""
    global _UnplugCallbackHandler
    if _UnplugCallbackHandler is None:
        _UnplugCallbackHandler = _build_callback_handler_class()
    return _UnplugCallbackHandler(hooks)


def __getattr__(name: str) -> Any:
    # Lazily expose the handler class so importing this module (e.g. for the
    # plain guard callables) never requires LangChain to be installed.
    global _UnplugCallbackHandler
    if name == "UnplugCallbackHandler":
        if _UnplugCallbackHandler is None:
            _UnplugCallbackHandler = _build_callback_handler_class()
        return _UnplugCallbackHandler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
