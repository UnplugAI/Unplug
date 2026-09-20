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


class TestUrlUserinfoWithoutPassword:
    """https://trusted.example@attacker.example/ is the host-confusion phish and missed."""

    def _subcategories(self, text: str) -> set[str]:
        scanner = MaliciousUrlScanner()
        return {f.subcategory for f in scanner.scan(_tainted(text), ExecutionContext())}

    @pytest.mark.parametrize(
        "url",
        [
            "https://trusted.example@attacker.example/",
            "https://user:pass@attacker.example/",
            "http://paypal.com@evil.test/login",
        ],
    )
    def test_userinfo_host_confusion_matches(self, url: str) -> None:
        assert "credentials_in_url" in self._subcategories(url)

    @pytest.mark.parametrize(
        "text",
        ["https://example.com/path", "contact us at mailto:a@b.com"],
    )
    def test_benign_urls_do_not_match(self, text: str) -> None:
        assert "credentials_in_url" not in self._subcategories(text)


class TestGitForcePushShortFlag:
    """git push -f is the form most often typed and matched no pattern."""

    def _subcategories(self, text: str) -> set[str]:
        scanner = DestructiveScanner()
        return {f.subcategory for f in scanner.scan(_tainted(text), ExecutionContext())}

    @pytest.mark.parametrize(
        "command",
        [
            "git push -f origin main",
            "git push --force",
            "git push --force-with-lease origin main",
            "git reset --hard HEAD~1",
            "git branch -D feature",
        ],
    )
    def test_destructive_git_matches(self, command: str) -> None:
        assert "git_destructive" in self._subcategories(command)

    @pytest.mark.parametrize(
        "command",
        ["git push origin main", "git push -foo", "git status"],
    )
    def test_safe_git_does_not_match(self, command: str) -> None:
        assert "git_destructive" not in self._subcategories(command)
