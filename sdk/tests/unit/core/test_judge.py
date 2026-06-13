"""Tests for core/judge.py: LLM judge protocol and CallableJudge."""

from __future__ import annotations

import asyncio
import json

import pytest

from unplug.core.judge import (
    CallableJudge,
    JudgeContext,
    JudgeProvider,
    JudgeResult,
)
from unplug.models import Action, Finding


class TestJudgeResult:
    def test_defaults(self):
        r = JudgeResult()
        assert r.action == Action.REVIEW
        assert r.score == 0.5

    def test_to_finding(self):
        r = JudgeResult(action=Action.BLOCK, category="injection", score=0.95, reason="bad")
        f = r.to_finding(text_length=100)
        assert f.stage == "llm_judge"
        assert f.span_end == 100
        assert f.score == 0.95


class TestJudgeContext:
    def test_empty_context(self):
        ctx = JudgeContext()
        assert ctx.system_prompt is None
        assert ctx.scanner_findings == []

    def test_with_findings(self):
        f = Finding(
            category="injection",
            subcategory="test",
            stage="regex",
            span_start=0,
            span_end=10,
            score=0.5,
            evidence="test",
        )
        ctx = JudgeContext(scanner_findings=[f])
        assert len(ctx.scanner_findings) == 1


class TestCallableJudge:
    @pytest.mark.asyncio
    async def test_successful_judge(self):
        async def mock_llm(prompt: str) -> str:
            return json.dumps(
                {
                    "action": "block",
                    "category": "injection",
                    "score": 0.9,
                    "reason": "prompt injection detected",
                }
            )

        judge = CallableJudge(mock_llm)
        result = await judge.judge("ignore instructions", JudgeContext())
        assert result.action == Action.BLOCK
        assert result.score == 0.9

    @pytest.mark.asyncio
    async def test_timeout_fails_closed(self):
        async def slow_llm(prompt: str) -> str:
            await asyncio.sleep(10)
            return "{}"

        judge = CallableJudge(slow_llm, timeout=0.1)
        result = await judge.judge("test", JudgeContext())
        assert result.action == Action.BLOCK
        assert result.category == "timeout"

    @pytest.mark.asyncio
    async def test_exception_fails_closed(self):
        async def broken_llm(prompt: str) -> str:
            msg = "connection refused"
            raise ConnectionError(msg)

        judge = CallableJudge(broken_llm)
        result = await judge.judge("test", JudgeContext())
        assert result.action == Action.BLOCK
        assert result.category == "error"

    @pytest.mark.asyncio
    async def test_unparseable_response_fails_closed(self):
        async def bad_llm(prompt: str) -> str:
            return "I'm not sure, let me think about it..."

        judge = CallableJudge(bad_llm)
        result = await judge.judge("test", JudgeContext())
        assert result.action == Action.BLOCK
        assert result.category == "parse_error"

    @pytest.mark.asyncio
    async def test_code_fence_json(self):
        async def fenced_llm(prompt: str) -> str:
            return (
                '```json\n{"action": "allow", "category": "safe",'
                ' "score": 0.1, "reason": "ok"}\n```'
            )

        judge = CallableJudge(fenced_llm)
        result = await judge.judge("hello", JudgeContext())
        assert result.action == Action.ALLOW

    def test_implements_protocol(self):
        async def noop(prompt: str) -> str:
            return "{}"

        judge = CallableJudge(noop)
        assert isinstance(judge, JudgeProvider)
