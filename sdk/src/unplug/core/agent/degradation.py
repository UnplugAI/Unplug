"""Adaptive degradation (homeostasis): monotonic tightening after risk escalation."""

from __future__ import annotations

import re

from unplug.config.agent_policy import DegradationConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.models import Finding

_PATTERN_CACHE: dict[tuple[str, ...], list[re.Pattern[str]]] = {}


def _compile(patterns: tuple[str, ...]) -> list[re.Pattern[str]]:
    cached = _PATTERN_CACHE.get(patterns)
    if cached is None:
        cached = [re.compile(p, re.IGNORECASE) for p in patterns]
        _PATTERN_CACHE[patterns] = cached
    return cached


def is_high_risk_tool(tool_name: str, config: DegradationConfig) -> bool:
    """True for OpenClaw-style high blast-radius tools (exec, browser, web)."""
    norm = tool_name.strip().lower()
    if ":" in norm:
        norm = norm.split(":")[-1]
    if "." in norm:
        norm = norm.split(".")[-1]
    if norm in {t.lower() for t in config.high_risk_tools}:
        return True
    return any(rx.search(norm) for rx in _compile(config.high_risk_patterns))


def sync_degradation_from_trajectory(
    context: ExecutionContext,
    trajectory_findings: list[Finding],
    config: DegradationConfig,
) -> None:
    """Raise degradation level monotonically when crescendo findings fire."""
    if not config.enabled:
        return
    for finding in trajectory_findings:
        if finding.subcategory == "crescendo_block":
            context.escalate_degradation(config.block_at_level)
        elif finding.subcategory == "crescendo_review":
            context.escalate_degradation(config.review_at_level)


def degraded_tool_findings(
    tool_call: ToolCall,
    context: ExecutionContext,
    config: DegradationConfig,
) -> list[Finding]:
    """Block or review high-risk tools when session degradation is elevated."""
    if not config.enabled or context.degradation_level < config.review_at_level:
        return []
    if not is_high_risk_tool(tool_call.tool_name, config):
        return []

    level = context.degradation_level
    if level >= config.block_at_level:
        return [
            Finding(
                category="degradation",
                subcategory="homeostasis_block_high_risk",
                stage="degradation",
                span_start=0,
                span_end=0,
                score=config.block_score,
                evidence=(
                    f"High-risk tool '{tool_call.tool_name}' blocked: security degradation "
                    f"level {level} (crescendo / trajectory escalation)"
                ),
            )
        ]

    return [
        Finding(
            category="degradation",
            subcategory="homeostasis_review_high_risk",
            stage="degradation",
            span_start=0,
            span_end=0,
            score=config.review_score,
            evidence=(
                f"High-risk tool '{tool_call.tool_name}' requires review: degradation level {level}"
            ),
        )
    ]
