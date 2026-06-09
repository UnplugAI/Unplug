"""Data leakage scanner — detects API keys, PII, and system prompt leakage."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import EVASION_ONLY_STAGES, Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding
from unplug.safeguards.base import RegexScanner

# Leet/base64 stages corrupt digit-heavy PII — use evasion stages only.
_LEAKAGE_NORMALIZE_STAGES = EVASION_ONLY_STAGES

LEAKAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "api_key_generic",
        re.compile(
            r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}",
        ),
    ),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
    ("email_address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_number", re.compile(r"\b(\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b")),
    ("ssn", re.compile(r"\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b")),
    ("ssn_compact", re.compile(r"\b\d{3}\d{2}\d{4}\b")),
    (
        "system_prompt_leak",
        re.compile(
            r"(?i)(system\s+prompt|my\s+instructions?\s+(are|say)|I\s+was\s+told\s+to)",
        ),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.80)


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

    def _should_scan(self, text: TaintedText) -> bool:
        return text.trust_level not in (TrustLevel.USER, TrustLevel.TRUSTED)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        normalized = norm_result.text
        seen: set[tuple[int, int, str]] = set()
        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(normalized):
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
