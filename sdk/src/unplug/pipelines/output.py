"""Output pipeline: secrets scan, leakage scan, sanitize."""

from __future__ import annotations

from typing import Any

from unplug.config.agent_policy import BoundaryConfig, DegradationConfig, TrajectoryConfig
from unplug.config.guard import PipelineConfig
from unplug.config.policy import ScanPolicy
from unplug.core.agent.boundaries import strip_boundary_markers
from unplug.core.context import ExecutionContext
from unplug.core.privacy.secrets import SecretsSanitizer
from unplug.core.redaction import apply_span_redactions
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding, ScanResult
from unplug.pipelines.base import BasePipeline
from unplug.scanners.base import BaseScanner


def _subtract_spans(
    finding: Finding,
    secret_spans: list[tuple[int, int]],
) -> list[Finding]:
    """Split a finding into copies covering the parts outside secret spans.

    Secret spans must be sorted and merged. Spans are half-open, matching
    ``apply_span_redactions()``.
    """
    residuals: list[tuple[int, int]] = []
    cursor = finding.span_start
    for start, end in secret_spans:
        if end <= start or start >= finding.span_end or end <= cursor:
            continue
        if start > cursor:
            residuals.append((cursor, start))
        cursor = end
        if cursor >= finding.span_end:
            break
    if cursor < finding.span_end:
        residuals.append((cursor, finding.span_end))
    return [finding.model_copy(update={"span_start": s, "span_end": e}) for s, e in residuals]


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
        resolved_policy = policy or self._config.policy
        text = self._extract_text(input_data)
        if text is None or not findings:
            return None
        if self._sanitizer is None:
            return apply_span_redactions(text, findings, resolved_policy)
        # Finding spans refer to the original text, so they must be applied
        # before sanitization (whose replacements change string lengths).
        # Secret spans are subtracted from finding spans so policy redaction
        # covers the residual parts while the sanitizer keeps its named
        # [REDACTED:<name>] placeholder for the secret itself.
        secret_spans = sorted(
            {(m.span_start, m.span_end) for m in self._sanitizer.sanitize(text).secrets_found}
        )
        merged_secret_spans: list[tuple[int, int]] = []
        for start, end in secret_spans:
            if end <= start:
                continue
            if merged_secret_spans and start <= merged_secret_spans[-1][1]:
                prev = merged_secret_spans[-1]
                merged_secret_spans[-1] = (prev[0], max(prev[1], end))
            else:
                merged_secret_spans.append((start, end))
        span_findings = [
            residual for f in findings for residual in _subtract_spans(f, merged_secret_spans)
        ]
        span_redacted = apply_span_redactions(text, span_findings, resolved_policy)
        if span_redacted is None:
            span_redacted = text
        return self._sanitizer.sanitize(span_redacted).clean_text
