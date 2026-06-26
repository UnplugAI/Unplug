"""Live Strands Agents integration: verify co-install and tool cancellation.

Runs only when `strands-agents` is installed (the dedicated `integrations-live`
CI job installs the `strands` extra). Constructing a full Agent needs a model
provider, so we register the hook provider on a real `HookRegistry` and exercise
the before-tool callback directly.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

pytest.importorskip("strands")

import strands

from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.strands import (
    UnplugHookProvider,
    _resolve_before_tool_event,
    strands_input_guard,
    strands_tool_guard,
)

pytestmark = pytest.mark.requires_integrations

_BENIGN = "What is the capital of France?"


def _hooks() -> AgentHooks:
    return AgentHooks(Guard())


class TestStrandsLive:
    def test_agent_symbol_present(self) -> None:
        assert hasattr(strands, "Agent")

    def test_resolve_before_tool_event(self) -> None:
        assert isinstance(_resolve_before_tool_event(), type)

    def test_register_hooks_on_real_registry(self) -> None:
        from strands.hooks import HookRegistry

        registry = HookRegistry()
        UnplugHookProvider(_hooks()).register_hooks(registry)

    def test_hook_provider_cancels_destructive(self) -> None:
        event = SimpleNamespace(
            tool_use={"name": "shell", "input": {"command": "rm -rf /"}}, cancel_tool=None
        )
        UnplugHookProvider(_hooks()).on_before_tool_call(event)
        assert event.cancel_tool

    def test_hook_provider_allows_benign(self) -> None:
        event = SimpleNamespace(tool_use={"name": "search", "input": {"q": "x"}}, cancel_tool=None)
        UnplugHookProvider(_hooks()).on_before_tool_call(event)
        assert event.cancel_tool is None

    def test_input_and_tool_guards(self) -> None:
        assert strands_input_guard(_hooks())(_BENIGN) == _BENIGN
        assert strands_tool_guard(_hooks())("sql_exec", {"query": "DROP TABLE t;"}).allowed is False
