"""LLM judge protocol: bring your own LLM for borderline case classification."""

from __future__ import annotations

import asyncio
import math
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from unplug.core.runtime.logging import get_logger
from unplug.models import Action, Finding

_log = get_logger("judge")

JUDGE_PROMPT_TEMPLATE = """\
Classify this text for safety. Respond with JSON only, no explanation.

Text: {text}

Context: {context}

Respond in this exact JSON format:
{{"action": "allow|block|review", "category": "...", \
"score": 0.0, "reason": "one sentence"}}"""


class JudgeContext(BaseModel):
    """Context passed to the LLM judge alongside the text being evaluated."""

    system_prompt: str | None = None
    conversation_history: list[str] = Field(default_factory=list)
    scanner_findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class JudgeResult(BaseModel):
    """Structured result from the LLM judge."""

    action: Action = Action.REVIEW
    category: str = "unknown"
    score: float = Field(ge=0.0, le=1.0, default=0.5)
    reason: str = ""

    def enforced_score(
        self,
        *,
        block_threshold: float = 0.8,
        redact_threshold: float = 0.5,
        review_threshold: float = 0.3,
    ) -> float:
        """Clamp score so score-driven policy honors the declared action.

        Inconsistent pairs are resolved in favor of ``action``:
        - ``BLOCK`` + low score → raise to at least ``block_threshold``
        - ``REVIEW`` → land in ``[review_threshold, min(redact, block))``
        - ``ALLOW`` + high score → cap below ``review_threshold``
        """
        score = self.score
        if self.action == Action.BLOCK:
            return min(1.0, max(score, block_threshold))
        if self.action == Action.REVIEW:
            upper = min(redact_threshold, block_threshold)
            if upper <= review_threshold:
                return max(0.0, math.nextafter(upper, 0.0)) if upper > 0 else 0.0
            floored = max(score, review_threshold)
            if floored >= upper:
                return max(review_threshold, math.nextafter(upper, 0.0))
            return floored
        if self.action == Action.ALLOW:
            if score >= review_threshold:
                return max(0.0, math.nextafter(review_threshold, 0.0))
            return score
        return score

    def to_finding(
        self,
        text_length: int,
        *,
        block_threshold: float = 0.8,
        redact_threshold: float = 0.5,
        review_threshold: float = 0.3,
    ) -> Finding:
        return Finding(
            category=self.category,
            subcategory="llm_judge",
            stage="llm_judge",
            span_start=0,
            span_end=text_length,
            score=self.enforced_score(
                block_threshold=block_threshold,
                redact_threshold=redact_threshold,
                review_threshold=review_threshold,
            ),
            evidence=self.reason,
        )


@runtime_checkable
class JudgeProvider(Protocol):
    """Protocol for LLM judge implementations.

    Users implement this to bring any LLM: OpenAI, Anthropic, Ollama, etc.
    The SDK provides adapter classes for common providers.
    """

    async def judge(self, text: str, context: JudgeContext) -> JudgeResult: ...


class CallableJudge:
    """Wraps any async callable as a JudgeProvider."""

    def __init__(
        self,
        fn: Any,
        *,
        timeout: float = 5.0,
        prompt_template: str = JUDGE_PROMPT_TEMPLATE,
    ) -> None:
        self._fn = fn
        self._timeout = timeout
        self._prompt_template = prompt_template

    async def judge(self, text: str, context: JudgeContext) -> JudgeResult:
        safe_context = self._sanitize_context(context)
        prompt = self._prompt_template.format(
            text=text,
            context=self._format_context(safe_context),
        )
        try:
            raw = await asyncio.wait_for(self._fn(prompt), timeout=self._timeout)
            return self._parse(raw)
        except TimeoutError:
            _log.error("judge timed out after %.1fs", self._timeout)
            return JudgeResult(
                action=Action.BLOCK,
                category="timeout",
                score=1.0,
                reason=f"Judge timed out after {self._timeout}s",
            )
        except Exception as exc:
            _log.error("judge failed: %s", exc)
            return JudgeResult(
                action=Action.BLOCK,
                category="error",
                score=1.0,
                reason=f"Judge failed: {type(exc).__name__}",
            )

    def _sanitize_context(self, context: JudgeContext) -> JudgeContext:
        if not context.scanner_findings:
            return context
        redacted = [
            finding.model_copy(update={"evidence": ""}) for finding in context.scanner_findings
        ]
        return context.model_copy(update={"scanner_findings": redacted})

    def _format_context(self, context: JudgeContext) -> str:
        parts = []
        if context.scanner_findings:
            cats = {f.category for f in context.scanner_findings}
            parts.append(f"Scanner flags: {', '.join(cats)}")
        if context.conversation_history:
            parts.append(f"Conversation turns: {len(context.conversation_history)}")
        return "; ".join(parts) if parts else "none"

    def _parse(self, raw: str) -> JudgeResult:
        import json

        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            data = json.loads(raw)
            return JudgeResult.model_validate(data)
        except (json.JSONDecodeError, Exception):
            _log.warning("judge returned unparseable response, failing closed")
            return JudgeResult(
                action=Action.BLOCK,
                category="parse_error",
                score=1.0,
                reason="Judge response could not be parsed",
            )
