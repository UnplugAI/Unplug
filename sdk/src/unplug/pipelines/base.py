"""Pipeline base class: shared timing, finding collection, result building."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from unplug.config.agent_policy import DegradationConfig, TrajectoryConfig
from unplug.config.guard import PipelineConfig
from unplug.config.policy import RedactionMode, ScanPolicy
from unplug.core.agent.degradation import sync_degradation_from_trajectory
from unplug.core.agent.trajectory import trajectory_findings
from unplug.core.context import ExecutionContext
from unplug.core.policy import decide_action, is_result_safe
from unplug.core.policy.sensitive_context import apply_sensitive_context_boost
from unplug.core.redaction import apply_span_redactions
from unplug.core.runtime.logging import get_logger
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.models import Action, Finding, ScanResult

_log = get_logger("pipelines")


class BasePipeline(ABC):
    """Abstract base for all enforcement pipelines."""

    name: str = ""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
        trajectory_config: TrajectoryConfig | None = None,
        degradation_config: DegradationConfig | None = None,
    ) -> None:
        self._config = config or PipelineConfig()
        self._metrics = metrics
        self._tagger = Tagger()
        self._trajectory_config = trajectory_config or TrajectoryConfig()
        self._degradation_config = degradation_config or DegradationConfig()

    @property
    def config(self) -> PipelineConfig:
        return self._config

    def run(self, input_data: Any, *, context: ExecutionContext | None = None) -> ScanResult:
        ctx = context or ExecutionContext()
        start = time.perf_counter()

        try:
            findings = list(self._execute(input_data, ctx))
            traj = trajectory_findings(ctx, self._trajectory_config)
            findings.extend(traj)
            sync_degradation_from_trajectory(ctx, traj, self._degradation_config)
        except Exception as exc:
            _log.error("pipeline %s failed: %s", self.name, exc)
            latency_ms = (time.perf_counter() - start) * 1000
            return ScanResult(
                safe=False,
                action=Action.BLOCK,
                risk_score=1.0,
                findings=[
                    Finding(
                        category=self.name,
                        subcategory="pipeline_error",
                        stage="error",
                        span_start=0,
                        span_end=0,
                        score=1.0,
                        evidence=f"Pipeline failed: {type(exc).__name__}",
                    )
                ],
                latency_ms=latency_ms,
            )
        latency_ms = (time.perf_counter() - start) * 1000

        text = self._extract_text(input_data) or ""
        policy = self._resolve_policy(ctx)
        findings, block_delta = apply_sensitive_context_boost(
            findings,
            text,
            enabled=policy.sensitive_context_enabled,
            score_boost=policy.sensitive_context_boost,
            block_threshold_delta=policy.sensitive_context_block_delta,
        )
        effective_policy = policy
        if block_delta > 0.0:
            effective_policy = policy.model_copy(
                update={"block_threshold": max(0.0, policy.block_threshold - block_delta)},
            )
        risk_score = max((f.score for f in findings), default=0.0)
        action = self._decide(risk_score, findings, text_len=len(text), policy=effective_policy)
        stages = list(dict.fromkeys(f.category for f in findings))
        redacted = None
        if findings and effective_policy.redaction_mode != RedactionMode.NONE:
            redacted = self._redact(input_data, findings, policy=effective_policy)
        if action == Action.ABSTAIN and redacted is None and findings:
            redacted = self._redact(input_data, findings, policy=effective_policy)

        result = ScanResult(
            safe=is_result_safe(action, effective_policy),
            action=action,
            risk_score=risk_score,
            findings=findings,
            redacted_text=redacted,
            latency_ms=latency_ms,
            stages_run=stages,
        )

        if self._metrics:
            self._metrics.record_pipeline(self.name, action=action.value, latency_ms=latency_ms)

        ctx.update_risk(risk_score)

        if action == Action.REVIEW:
            log_fn = _log.info
        else:
            log_fn = _log.warning if 0.3 <= risk_score < 0.5 else _log.info
        log_fn(
            "pipeline %s: action=%s risk=%.2f findings=%d latency=%.1fms",
            self.name,
            action.value,
            risk_score,
            len(findings),
            latency_ms,
        )

        return result

    @abstractmethod
    def _execute(self, input_data: Any, context: ExecutionContext) -> list[Finding]:
        """Core pipeline logic. Return findings."""
        ...

    def _resolve_policy(self, context: ExecutionContext) -> ScanPolicy:
        if context.scan_policy is not None:
            return context.scan_policy
        return self._config.policy

    def _decide(
        self,
        risk_score: float,
        findings: list[Finding],
        *,
        text_len: int,
        policy: ScanPolicy,
    ) -> Action:
        return decide_action(
            findings,
            text_len=text_len,
            policy=policy,
            risk_score=risk_score,
        )

    def _redact(
        self,
        input_data: Any,
        findings: list[Finding],
        *,
        policy: ScanPolicy,
    ) -> str | None:
        text = self._extract_text(input_data)
        if text is None:
            return None
        return apply_span_redactions(text, findings, policy)

    def _extract_text(self, input_data: Any) -> str | None:
        if isinstance(input_data, str):
            return input_data
        if isinstance(input_data, TaintedText):
            return input_data.text
        return None

    def _ensure_tainted(
        self,
        text: str | TaintedText,
        default_trust: TrustLevel = TrustLevel.USER,
        origin: str = "",
    ) -> TaintedText:
        if isinstance(text, TaintedText):
            return text
        return self._tagger.tag(text, default_trust, origin or self.name)
