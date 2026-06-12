"""Secrets scanner — exact-match detection using SecretsRegistry."""

from __future__ import annotations

from collections.abc import Generator

from unplug.core.canary import CANARY_NAME_PREFIX
from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.safeguards.base import BaseScanner

_DEFAULT_CONFIG = ScannerConfig(base_score=0.99)


class SecretsScanner(BaseScanner):
    name = "secrets"

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        if context.secrets_registry is None:
            return

        for m in context.secrets_registry.contains(text.text):
            if m.secret_name.startswith(CANARY_NAME_PREFIX):
                yield Finding(
                    category="leakage",
                    subcategory="prompt_leak_canary",
                    stage="canary",
                    span_start=m.span_start,
                    span_end=m.span_end,
                    score=self._config.base_score,
                    evidence=f"Canary token '{m.secret_name}' leaked into output",
                    replacement="[REDACTED:canary]",
                )
                continue
            yield Finding(
                category="secrets",
                subcategory=f"registered_secret:{m.secret_name}",
                stage="regex",
                span_start=m.span_start,
                span_end=m.span_end,
                score=self._config.base_score,
                evidence=f"Registered secret '{m.secret_name}' found in output",
                replacement=None,
            )
