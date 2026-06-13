"""Safeguard base classes: regex and model-based scanners."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import ClassVar, Protocol, runtime_checkable

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.runtime.logging import get_logger
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.ml.models import ModelProvider, ModelSpec, NullModelProvider
from unplug.models import Finding

_log = get_logger("safeguards")


@runtime_checkable
class Scanner(Protocol):
    """Minimal protocol: anything with name + scan() works."""

    name: str

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]: ...


class BaseScanner(ABC):
    """Abstract base for all safeguards."""

    name: str = ""

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        self._config = config or ScannerConfig()
        self._metrics = metrics

    @property
    def config(self) -> ScannerConfig:
        return self._config

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        if not self._config.enabled:
            return []
        if not self._should_scan(text):
            return []

        start = time.perf_counter()
        try:
            findings = list(self._scan(text, context))
        except Exception as exc:
            _log.error("safeguard %s failed: %s", self.name, exc)
            findings = [
                Finding(
                    category=self.name,
                    subcategory="scanner_error",
                    stage="error",
                    span_start=0,
                    span_end=len(text.text),
                    score=1.0,
                    evidence=f"Scanner failed: {type(exc).__name__}",
                )
            ]
        elapsed_ms = (time.perf_counter() - start) * 1000

        if self._metrics:
            self._metrics.record_scanner(
                self.name, findings_count=len(findings), latency_ms=elapsed_ms
            )

        return findings

    def _should_scan(self, text: TaintedText) -> bool:
        return True

    @abstractmethod
    def _scan(
        self, text: TaintedText, context: ExecutionContext
    ) -> Generator[Finding, None, None]: ...


class RegexScanner(BaseScanner):
    """Base for regex pattern safeguards."""

    _patterns: ClassVar[list[tuple[str, re.Pattern[str]]]] = []

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        raw = self._get_scan_text(text)
        yield from self._match_patterns(raw, text)

    def _get_scan_text(self, text: TaintedText) -> str:
        return text.text

    def _match_patterns(self, raw: str, text: TaintedText) -> Generator[Finding, None, None]:
        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(raw):
                yield self._make_finding(subcategory, match.start(), match.end(), raw, text)

    def _make_finding(
        self,
        subcategory: str,
        span_start: int,
        span_end: int,
        raw: str,
        text: TaintedText,
    ) -> Finding:
        score = self._compute_score(subcategory, text)
        return Finding(
            category=self.name,
            subcategory=subcategory,
            stage="regex",
            span_start=span_start,
            span_end=span_end,
            score=score,
            evidence=self._make_evidence(subcategory),
            replacement=self._get_replacement(subcategory),
        )

    def _compute_score(self, subcategory: str, text: TaintedText) -> float:
        return self._config.base_score

    def _make_evidence(self, subcategory: str) -> str:
        return f"{self.name}: {subcategory}"

    def _get_replacement(self, subcategory: str) -> str | None:
        return None


class ModelScanner(BaseScanner):
    """Base for ML-backed safeguards."""

    model_spec: ModelSpec | None = None

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
        model: ModelProvider | None = None,
    ) -> None:
        super().__init__(config=config, metrics=metrics)
        self._model = model or NullModelProvider(
            self.model_spec or ModelSpec(name=self.name, backend="null")
        )

    @property
    def model(self) -> ModelProvider:
        return self._model

    def load_model(self) -> None:
        self._model.load()

    def unload_model(self) -> None:
        self._model.unload()
