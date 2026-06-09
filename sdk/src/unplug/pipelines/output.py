"""Output pipeline — secrets scan, leakage scan, sanitize."""

from __future__ import annotations

from typing import Any

from unplug.config.agent_policy import BoundaryConfig, DegradationConfig, TrajectoryConfig
from unplug.config.policy import ScanPolicy
from unplug.core.boundaries import strip_boundary_markers
from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext
from unplug.core.secrets import SecretsSanitizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Action, Finding, ScanResult
from unplug.pipelines.base import BasePipeline
from unplug.safeguards.base import BaseScanner


class OutputPipeline(BasePipeline):
    name = "output"

    def __init__(
        self,
        secrets_sanitizer: SecretsSanitizer | None = None,
        leakage_scanner: BaseScanner | None = None,
        secrets_scanner: BaseScanner | None = None,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
        trajectory_config: TrajectoryConfig | None = None,
        boundary_config: BoundaryConfig | None = None,
        degradation_config: DegradationConfig | None = None,
    ) -> None:
        super().__init__(
            config=config,
            metrics=metrics,
            trajectory_config=trajectory_config,
            degradation_config=degradation_config,
        )
        self._sanitizer = secrets_sanitizer
        self._leakage = leakage_scanner
        self._secrets = secrets_scanner
        self._boundary_config = boundary_config or BoundaryConfig()

    def run(
        self,
        text: str | TaintedText,
        *,
        context: ExecutionContext | None = None,
    ) -> ScanResult:
        tainted = self._ensure_tainted(text, TrustLevel.TOOL_OUTPUT, "output_pipeline")
        result = super().run(tainted, context=context)
        if not self._boundary_config.strip_on_output:
            return result
        raw = self._extract_text(tainted)
        if raw is None:
            return result
        stripped = strip_boundary_markers(raw)
        if stripped == raw:
            return result
        redacted = result.redacted_text or stripped
        if result.redacted_text:
            redacted = strip_boundary_markers(result.redacted_text)
        return result.model_copy(update={"redacted_text": redacted})

    def _execute(self, input_data: TaintedText, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        if self._secrets:
            findings.extend(self._secrets.scan(input_data, context))
        if self._leakage:
            findings.extend(self._leakage.scan(input_data, context))
        return findings

    def _decide(
        self,
        risk_score: float,
        findings: list[Finding],
        *,
        text_len: int = 0,
        policy: ScanPolicy | None = None,
    ) -> Action:
        _ = text_len, policy
        if risk_score >= self._config.thresholds.block:
            return Action.BLOCK
        if risk_score >= self._config.thresholds.redact:
            return Action.REDACT
        return Action.ALLOW

    def _redact(
        self,
        input_data: Any,
        findings: list[Finding],
        *,
        policy: ScanPolicy | None = None,
    ) -> str | None:
        _ = policy
        text = self._extract_text(input_data)
        if text is None or not findings:
            return None
        if self._sanitizer:
            return self._sanitizer.sanitize(text).clean_text
        return super()._redact(
            input_data,
            findings,
            policy=policy or self._config.policy,
        )
