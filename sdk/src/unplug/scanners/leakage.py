"""Data leakage scanner: detects API keys, PII, and system prompt leakage."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import EVASION_ONLY_STAGES, Normalizer
from unplug.core.pattern_loader import leakage_patterns, secret_only_patterns
from unplug.core.privacy.luhn import luhn_valid
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.data.maps_loader import default_scanner_config
from unplug.models import Finding
from unplug.scanners.base import RegexScanner

# Leet/base64 stages corrupt digit-heavy PII: use evasion stages only.
_LEAKAGE_NORMALIZE_STAGES = EVASION_ONLY_STAGES

LEAKAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = leakage_patterns()
_USER_SECRET_SUBCATEGORIES = frozenset(name for name, _ in secret_only_patterns())


_DEFAULT_CONFIG = default_scanner_config("leakage")


class LeakageScanner(RegexScanner):
    name = "leakage"
    _patterns = LEAKAGE_PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer(stages=_LEAKAGE_NORMALIZE_STAGES)

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        if not self._config.enabled:
            return []
        if text.trust_level == TrustLevel.TRUSTED:
            return []
        if text.trust_level == TrustLevel.USER:
            from unplug.config.policy import ScanPolicy

            policy = context.scan_policy or ScanPolicy()
            if not policy.scan_user_secrets:
                return []
        return super().scan(text, context)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        normalized = norm_result.text
        seen: set[tuple[int, int, str]] = set()
        for subcategory, pattern in self._patterns:
            skip_user = (
                text.trust_level == TrustLevel.USER
                and subcategory not in _USER_SECRET_SUBCATEGORIES
            )
            if skip_user:
                continue
            for match in pattern.finditer(normalized):
                if subcategory == "credit_card":
                    digits = re.sub(r"\D", "", match.group(0))
                    if not luhn_valid(digits):
                        continue
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                key = (span_start, span_end, subcategory)
                if key in seen:
                    continue
                seen.add(key)
                score = self._compute_score(subcategory, text)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=score,
                    evidence=self._make_evidence(subcategory),
                    replacement=self._get_replacement(subcategory),
                )

    def _get_replacement(self, subcategory: str) -> str | None:
        return None

    def _make_evidence(self, subcategory: str) -> str:
        return f"Potential data leakage: {subcategory}"
