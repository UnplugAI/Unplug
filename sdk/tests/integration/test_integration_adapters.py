"""Extended integration adapter tests."""

from __future__ import annotations

import pytest

from unplug import Guard
from unplug.integrations.agno import agno_post_run_hook, agno_pre_run_hook, agno_tool_hook
from unplug.integrations.autogen import (
    autogen_reply_hook,
    autogen_user_message_hook,
)
from unplug.integrations.crewai import (
    crewai_output_guard,
    crewai_task_input_guard,
)
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.langgraph import langgraph_input_node, langgraph_tool_guard
from unplug.integrations.llama_index import UnplugNodePostprocessor
from unplug.integrations.pydantic_ai import pydantic_ai_input_validator, pydantic_ai_tool_guard
from unplug.integrations.semantic_kernel import (
    semantic_kernel_function_filter,
    semantic_kernel_prompt_filter,
    semantic_kernel_response_filter,
)


class TestCrewAiHelpers:
    def test_task_guard_allows_benign(self) -> None:
        crewai_task_input_guard(AgentHooks(Guard()))("Summarize this article.")

    def test_output_guard(self) -> None:
        out = crewai_output_guard(AgentHooks(Guard()))("Done.")
        assert out


class TestAutoGenHelpers:
    def test_user_message_allows_benign(self) -> None:
        msg = autogen_user_message_hook(AgentHooks(Guard()))({"content": "Hi"})
        assert msg["content"] == "Hi"

    def test_reply_hook(self) -> None:
        assert autogen_reply_hook(AgentHooks(Guard()))("OK") == "OK"


class TestLlamaIndexHelpers:
    def test_dict_nodes(self) -> None:
        post = UnplugNodePostprocessor()
        kept = post.postprocess_nodes([{"text": "Hello world", "metadata": {}}])
        assert len(kept) == 1


class TestPydanticAiHelpers:
    def test_tool_guard(self) -> None:
        d = pydantic_ai_tool_guard(AgentHooks(Guard()))("search", {"q": "x"})
        assert d.allowed is True


class TestSemanticKernelHelpers:
    def test_prompt_filter_benign(self) -> None:
        out = semantic_kernel_prompt_filter(AgentHooks(Guard()))("Hello")
        assert out == "Hello"

    def test_function_filter_blocks(self) -> None:
        d = semantic_kernel_function_filter(AgentHooks(Guard()))("shell", {"command": "rm -rf /"})
        assert d.allowed is False

    def test_response_filter(self) -> None:
        assert semantic_kernel_response_filter(AgentHooks(Guard()))("Hi") == "Hi"


class TestLangGraphAndAgnoRegression:
    """Keep parity with test_integrations.py."""

    def test_langgraph_input(self) -> None:
        node = langgraph_input_node(AgentHooks(Guard()))
        node({"messages": [{"role": "user", "content": "Hello"}]})

    def test_agno_pre(self) -> None:
        agno_pre_run_hook(AgentHooks(Guard()))("Hello")

    def test_agno_tool(self) -> None:
        agno_tool_hook(AgentHooks(Guard()))("search", {"q": "x"})

    def test_langgraph_tool(self) -> None:
        assert langgraph_tool_guard(AgentHooks(Guard()))("x", {}).allowed is True

    def test_agno_post_blocks_leak(self) -> None:
        with pytest.raises(RuntimeError):
            agno_post_run_hook(AgentHooks(Guard()))("sk-live-abcdef1234567890abcdef1234567890")

    def test_pydantic_input_benign(self) -> None:
        assert pydantic_ai_input_validator(AgentHooks(Guard()))("Hi") == "Hi"
