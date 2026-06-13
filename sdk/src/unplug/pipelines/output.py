"""Output pipeline: secrets scan, leakage scan, sanitize."""

from __future__ import annotations

from typing import Any

from unplug.config.agent_policy import BoundaryConfig, DegradationConfig, TrajectoryConfig
from unplug.config.policy import ScanPolicy
from unplug.core.agent.boundaries import strip_boundary_markers
from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext
from unplug.core.privacy.secrets import SecretsSanitizer
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding, ScanResult
from unplug.pipelines.base import BasePipeline
from unplug.scanners.base import BaseScanner


class OutputPipeline(BasePipeline):
    name = "output"

    def __init__(
        self,
        secrets_sanitizer: SecretsSanitizer | None = None,
        leakage_scanner: BaseScanner | None = None,
        secrets_scanner: BaseScanner | None = None,
        url_scanner: BaseScanner | None = None,
        pii_scanner: BaseScanner | None = None,
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
        self._urls = url_scanner
        self._pii = pii_scanner
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
        secret_spans: set[tuple[int, int]] = set()
        if self._secrets:
            secret_findings = list(self._secrets.scan(input_data, context))
            for finding in secret_findings:
                secret_spans.add((finding.span_start, finding.span_end))
            findings.extend(secret_findings)
        if self._leakage:
            for finding in self._leakage.scan(input_data, context):
                span = (finding.span_start, finding.span_end)
                if span in secret_spans:
                    continue
                findings.append(finding)
        if self._urls:
            findings.extend(self._urls.scan(input_data, context))
        if self._pii:
            findings.extend(self._pii.scan(input_data, context))
        return findings

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
