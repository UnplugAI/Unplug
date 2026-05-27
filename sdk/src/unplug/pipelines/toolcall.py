"""Tool call pipeline — destructive check, taint check, financial check, session policy."""

from __future__ import annotations

from typing import Any

from unplug.config.agent_policy import IntentConfig, TrajectoryConfig
from unplug.config.tools import ToolPolicyConfig
from unplug.core.approval import build_approval_request
from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.intent import check_intent_mismatch
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TrustLevel
from unplug.models import Action, Finding, ScanResult
from unplug.pipelines.base import BasePipeline
from unplug.safeguards.base import BaseScanner


class ToolCallPipeline(BasePipeline):
    name = "toolcall"

    def __init__(
        self,
        destructive_scanner: BaseScanner | None = None,
        financial_scanner: BaseScanner | None = None,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
        tool_policy: ToolPolicyConfig | None = None,
        intent_config: IntentConfig | None = None,
        trajectory_config: TrajectoryConfig | None = None,
    ) -> None:
        super().__init__(config=config, metrics=metrics, trajectory_config=trajectory_config)
        self._destructive = destructive_scanner
        self._financial = financial_scanner
        self._tool_policy = tool_policy or ToolPolicyConfig()
        self._intent_config = intent_config or IntentConfig()

    def run(
        self,
        tool_call: ToolCall,
        *,
        context: ExecutionContext | None = None,
    ) -> ScanResult:
        ctx = context or ExecutionContext()
        result = super().run(tool_call, context=ctx)
        if result.action != Action.REVIEW or not self._tool_policy.enabled:
            return result
        approval = build_approval_request(
            tool_name=tool_call.tool_name,
            arguments=tool_call.arguments,
            findings=result.findings,
            risk_score=result.risk_score,
            action=result.action,
            session_tainted=ctx.is_session_tainted,
        )
        return result.model_copy(update={"approval": approval})

    def _execute(self, input_data: ToolCall, context: ExecutionContext) -> list[Finding]:
        text_parts = [input_data.tool_name]
        text_parts.extend(self._extract_string_values(input_data.arguments))
        scan_text = " ".join(text_parts)
        tainted = self._tagger.tag(scan_text, TrustLevel.USER, "tool_call_pipeline")

        findings: list[Finding] = []

        if self._destructive:
            findings.extend(self._destructive.scan(tainted, context))

        findings.extend(self._check_taint(input_data, findings))
        findings.extend(self._check_session_taint(input_data, context))
        findings.extend(
            check_intent_mismatch(
                input_data,
                context,
                self._intent_config,
                is_side_effect=self._tool_policy.is_side_effect(input_data.tool_name),
            )
        )

        if self._financial:
            findings.extend(self._financial.scan(tainted, context))

        return findings

    @staticmethod
    def _extract_string_values(obj: Any) -> list[str]:
        """Recursively extract all string values from a nested dict/list."""
        values: list[str] = []
        if isinstance(obj, str):
            values.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                values.extend(ToolCallPipeline._extract_string_values(v))
        elif isinstance(obj, list):
            for item in obj:
                values.extend(ToolCallPipeline._extract_string_values(item))
        return values

    def _decide(
        self,
        risk_score: float,
        findings: list[Finding],
        *,
        text_len: int = 0,
        policy: object | None = None,
    ) -> Action:
        _ = text_len, policy
        t = self._config.thresholds
        if risk_score >= t.block:
            return Action.BLOCK
        if risk_score >= t.review:
            return Action.REVIEW
        return Action.ALLOW

    def _redact(
        self,
        input_data: Any,
        findings: list[Finding],
        *,
        policy: object | None = None,
    ) -> str | None:
        _ = input_data, findings, policy
        return None

    def _check_session_taint(self, tool_call: ToolCall, context: ExecutionContext) -> list[Finding]:
        """CaMeL-style: tainted session + side-effect tool → review (unless pre-approved)."""
        if not self._tool_policy.enabled or not self._tool_policy.session_taint_enabled:
            return []
        if not context.is_session_tainted:
            return []
        if tool_call.approved is True:
            return []
        if not self._tool_policy.is_side_effect(tool_call.tool_name):
            return []

        score = self._tool_policy.tainted_side_effect_review_score
        triggers = ", ".join(context.taint_triggers[:3]) or "unknown"
        return [
            Finding(
                category="taint",
                subcategory="session_taint_side_effect",
                stage="tool_policy",
                span_start=0,
                span_end=0,
                score=score,
                evidence=(
                    f"Side-effect tool '{tool_call.tool_name}' blocked for review: "
                    f"session tainted ({triggers})"
                ),
            )
        ]

    def _check_taint(self, tool_call: ToolCall, existing: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        has_destructive = any(f.category == "destructive" for f in existing)

        for source in tool_call.taint_sources:
            if source.trust_level in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN):
                score = 0.90 if has_destructive else 0.60
                findings.append(
                    Finding(
                        category="taint",
                        subcategory="untrusted_source_in_tool_call",
                        stage="taint_check",
                        span_start=0,
                        span_end=0,
                        score=score,
                        evidence=(
                            f"Tool call arguments influenced by untrusted "
                            f"{source.trust_level.value} data from '{source.origin}'"
                        ),
                    )
                )
            elif source.trust_level in (TrustLevel.RETRIEVED, TrustLevel.TOOL_OUTPUT):
                if has_destructive or self._tool_policy.is_side_effect(tool_call.tool_name):
                    sub = (
                        "retrieved_source_in_destructive_call"
                        if has_destructive
                        else "retrieved_source_in_side_effect"
                    )
                    findings.append(
                        Finding(
                            category="taint",
                            subcategory=sub,
                            stage="taint_check",
                            span_start=0,
                            span_end=0,
                            score=0.85,
                            evidence=(
                                f"Tool call '{tool_call.tool_name}' uses arguments "
                                f"from {source.trust_level.value} data ('{source.origin}')"
                            ),
                        )
                    )

        return findings
