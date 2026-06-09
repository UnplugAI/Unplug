"""Financial scanner — catches crypto addresses, payment APIs, and transfer patterns."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import EVASION_ONLY_STAGES, Normalizer, NormalizeResult
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding
from unplug.safeguards.base import BaseScanner

_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("btc_address_legacy", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
    ("btc_address_segwit", re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,87}\b")),
    ("eth_address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
]

_PAYMENT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "stripe_api",
        re.compile(r"(?i)\b(stripe\.(charges|paymentIntents|transfers|subscriptions)\.create)\b"),
    ),
    ("paypal_api", re.compile(r"(?i)\b(paypal\.(payment|Payout)\.create)\b")),
    (
        "wire_transfer",
        re.compile(r"(?i)\b(wire\s+transfer|bank\s+transfer|SWIFT\s+transfer|IBAN\s*[:=]\s*\S+)\b"),
    ),
]

_AMOUNT_PATTERN = re.compile(
    r"(?i)\b(send|transfer|pay|withdraw|deposit)\s+\$?\s*([\d,]+\.?\d*)\s*(USD|EUR|GBP|BTC|ETH|SOL)?\b"
)

_DEFAULT_CONFIG = ScannerConfig(base_score=0.70)


def _parse_amount(raw: str) -> float:
    return float(raw.replace(",", ""))


class FinancialScanner(BaseScanner):
    name = "financial"

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
        *,
        auto_block_threshold: float = 10_000.0,
        review_threshold: float = 100.0,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self.auto_block_threshold = auto_block_threshold
        self.review_threshold = review_threshold
        self._normalizer = Normalizer(stages=EVASION_ONLY_STAGES)

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        untrusted = text.trust_level in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN)
        boost = self._config.trust_boost if untrusted else 0.0

        yield from self._scan_crypto(norm_result, text, boost)
        yield from self._scan_payments(norm_result, text, boost)
        yield from self._scan_amounts(norm_result, text, boost)

    def _scan_crypto(
        self,
        norm_result: NormalizeResult,
        text: TaintedText,
        boost: float,
    ) -> Generator[Finding, None, None]:
        normalized = norm_result.text
        for subcategory, pattern in _CRYPTO_PATTERNS:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                yield Finding(
                    category="financial",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=min(0.80, 0.70 + boost),
                    evidence=f"Crypto address detected: {subcategory}",
                )

    def _scan_payments(
        self,
        norm_result: NormalizeResult,
        text: TaintedText,
        boost: float,
    ) -> Generator[Finding, None, None]:
        normalized = norm_result.text
        for subcategory, pattern in _PAYMENT_PATTERNS:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                yield Finding(
                    category="financial",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=min(0.95, 0.85 + boost),
                    evidence=f"Payment API detected: {subcategory}",
                )

    def _scan_amounts(
        self,
        norm_result: NormalizeResult,
        text: TaintedText,
        boost: float,
    ) -> Generator[Finding, None, None]:
        normalized = norm_result.text
        for match in _AMOUNT_PATTERN.finditer(normalized):
            try:
                amount = _parse_amount(match.group(2))
            except ValueError:
                continue

            if amount >= self.auto_block_threshold:
                score = min(1.0, 0.95 + boost * 0.5)
                evidence = f"Large financial transfer: ${amount:,.2f} (above auto-block threshold)"
            elif amount >= self.review_threshold:
                score = min(0.70, 0.60 + boost)
                evidence = f"Financial transfer: ${amount:,.2f} (above review threshold)"
            else:
                continue

            span_start, span_end = norm_result.to_original_span(match.start(), match.end())
            yield Finding(
                category="financial",
                subcategory="transfer_amount",
                stage="regex",
                span_start=span_start,
                span_end=span_end,
                score=score,
                evidence=evidence,
            )
