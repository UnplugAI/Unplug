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
