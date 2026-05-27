"""Input pipeline — taint, normalize, scan, decide."""

from __future__ import annotations

import asyncio
from typing import Any

from unplug.config.agent_policy import BoundaryConfig, TrajectoryConfig
from unplug.core.boundaries import maybe_wrap_untrusted
from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext
from unplug.core.encodings import EncodingClassifier, scan_encoding_blobs
from unplug.core.judge import JudgeContext, JudgeProvider
from unplug.core.logging import get_logger
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel, trust_level_from_source
from unplug.models import Finding, Source
from unplug.pipelines.base import BasePipeline
from unplug.safeguards.base import BaseScanner

_log = get_logger("pipelines.input")


class InputPipeline(BasePipeline):
    name = "input"

    def __init__(
        self,
        scanners: list[BaseScanner],
        normalizer: Normalizer | None = None,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
        judge: JudgeProvider | Any | None = None,
        judge_low: float = 0.3,
        judge_high: float = 0.8,
        encoding_classifier: EncodingClassifier | None = None,
        scan_encodings: bool = True,
        boundary_config: BoundaryConfig | None = None,
        trajectory_config: TrajectoryConfig | None = None,
    ) -> None:
        super().__init__(config=config, metrics=metrics, trajectory_config=trajectory_config)
        self._scanners = scanners
        self._normalizer = normalizer or Normalizer()
        self._judge = judge
        self._judge_low = judge_low
        self._judge_high = judge_high
        self._encoding_classifier = encoding_classifier
        self._scan_encodings = scan_encodings
        self._boundary_config = boundary_config or BoundaryConfig()

    def run(
        self,
        text: str | TaintedText,
        *,
        source: Source | TrustLevel = TrustLevel.USER,
        context: ExecutionContext | None = None,
    ) -> Any:
        if isinstance(text, TaintedText):
            tainted = text
        else:
            body = text
            src = source
            body, _ = maybe_wrap_untrusted(
                body,
                source=src,
                config=self._boundary_config,
            )
            if isinstance(source, Source):
                trust = trust_level_from_source(source)
            else:
                trust = source
            tainted = self._tagger.tag(body, trust, "input_pipeline")

        return super().run(tainted, context=context)

    def _execute(self, input_data: TaintedText, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        if self._scan_encodings:
            findings.extend(
                scan_encoding_blobs(input_data.text, classifier=self._encoding_classifier)
            )

        regex_scanners: list[BaseScanner] = []
        ml_scanners: list[BaseScanner] = []
        allowed = context.allowed_scanners
        for scanner in self._scanners:
            if allowed is not None and scanner.name not in allowed:
                continue
            if scanner.name == "injection_ml":
                ml_scanners.append(scanner)
            else:
                regex_scanners.append(scanner)

        for scanner in regex_scanners:
            findings.extend(scanner.scan(input_data, context))

        block_threshold = self._config.thresholds.block
        risk = max((f.score for f in findings), default=0.0)
        if ml_scanners and risk < block_threshold:
            for scanner in ml_scanners:
                findings.extend(scanner.scan(input_data, context))

        if self._judge is not None:
            findings.extend(self._maybe_judge(input_data, findings, context))
        return findings

    def _maybe_judge(
        self,
        input_data: TaintedText,
        findings: list[Finding],
        context: ExecutionContext,
    ) -> list[Finding]:
        risk = max((f.score for f in findings), default=0.0)
        if risk < self._judge_low or risk >= self._judge_high:
            return []
        judge_ctx = JudgeContext(scanner_findings=findings)
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                result = asyncio.run(self._judge.judge(input_data.text, judge_ctx))
            else:
                future = asyncio.run_coroutine_threadsafe(
                    self._judge.judge(input_data.text, judge_ctx),
                    loop,
                )
                timeout = self._config.judge_timeout
                result = future.result(timeout=timeout)
        except Exception as exc:
            _log.error("input pipeline judge failed: %s", exc)
            return [
                Finding(
                    category="judge",
                    subcategory="judge_error",
                    stage="llm_judge",
                    span_start=0,
                    span_end=len(input_data.text),
                    score=1.0,
                    evidence=f"Judge failed: {type(exc).__name__}",
                )
            ]
        return [result.to_finding(len(input_data.text))]
