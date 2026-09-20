"""Literals a security audit found the pattern files missing.

Each test names the shape that scored zero before the fix. They are regression tests in the
strict sense: every HIT case here returned no finding on the prior patterns.
"""

from __future__ import annotations

import pytest

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText, Tagger, TrustLevel
from unplug.scanners.destructive import DestructiveScanner
from unplug.scanners.leakage import LeakageScanner
from unplug.scanners.urls import MaliciousUrlScanner


def _leak(text: str, trust: TrustLevel = TrustLevel.USER) -> list[str]:
    scanner = LeakageScanner()
    tagged = Tagger().tag(text, trust, "test")
    return [f.subcategory for f in scanner.scan(tagged, ExecutionContext())]


def _tainted(text: str, trust: TrustLevel = TrustLevel.TOOL_OUTPUT) -> TaintedText:
    return TaintedText(text=text, trust_level=trust, origin="test")


class TestPrivateKeyHeaderLabels:
    """OPENSSH is the ssh-keygen default since OpenSSH 7.8 and matched nothing."""

    @pytest.mark.parametrize(
        "label",
        ["OPENSSH", "RSA", "EC", "DSA", "ENCRYPTED", ""],
    )
    def test_pem_label_matches(self, label: str) -> None:
        spacer = f"{label} " if label else ""
        text = f"-----BEGIN {spacer}PRIVATE KEY-----"
        assert "private_key_header" in _leak(text)

    @pytest.mark.parametrize(
        "text",
        [
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN OPENSSH PUBLIC KEY-----",
        ],
    )
    def test_non_private_blocks_do_not_match(self, text: str) -> None:
        assert "private_key_header" not in _leak(text)


class TestCreditCardBrands:
    """The old alternation encoded 16 and 19 digit groupings only."""

    @pytest.mark.parametrize(
        "number",
        [
            "378282246310005",  # Amex, 15 digits
            "38520000023237",  # Diners, 14 digits
            "4111111111111111",  # Visa, 16 digits
            "4111 1111 1111 1111",
            "5555-5555-5555-4444",
        ],
    )
    def test_luhn_valid_card_matches(self, number: str) -> None:
        assert "credit_card" in _leak(number, TrustLevel.TOOL_OUTPUT)

    @pytest.mark.parametrize(
        "text",
        [
            "4111111111111112",  # fails Luhn
            "12345",
            "order 1234 5678",
        ],
    )
    def test_non_card_digits_do_not_match(self, text: str) -> None:
        assert "credit_card" not in _leak(text, TrustLevel.TOOL_OUTPUT)
