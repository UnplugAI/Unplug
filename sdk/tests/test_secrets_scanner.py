"""Tests for scanners/secrets.py — SecretsScanner using registry."""

from unplug.core.context import ExecutionContext
from unplug.core.secrets import SecretsRegistry
from unplug.core.taint import TaintedText, TrustLevel
from unplug.safeguards.secrets import SecretsScanner


def _make_text(text: str, trust: TrustLevel = TrustLevel.TOOL_OUTPUT) -> TaintedText:
    return TaintedText(text=text, trust_level=trust, origin="test")


class TestSecretsScanner:
    def test_detects_registered_secret(self):
        registry = SecretsRegistry()
        registry.register("API_KEY", "sk-test-secret-key-12345678901234567890")
        ctx = ExecutionContext(secrets_registry=registry)
        scanner = SecretsScanner()

        text = _make_text("Your key is sk-test-secret-key-12345678901234567890")
        findings = scanner.scan(text, ctx)
        assert len(findings) >= 1
        assert findings[0].category == "secrets"
        assert "API_KEY" in findings[0].subcategory
        assert findings[0].score == 0.99
        assert findings[0].replacement is None

    def test_correct_span(self):
        registry = SecretsRegistry()
        secret = "my-secret-value-that-is-long-enough"
        registry.register("TOKEN", secret)
        ctx = ExecutionContext(secrets_registry=registry)
        scanner = SecretsScanner()

        text = _make_text(f"prefix {secret} suffix")
        findings = scanner.scan(text, ctx)
        exact = [f for f in findings if "TOKEN" in f.subcategory]
        assert len(exact) == 1
        assert text.text[exact[0].span_start : exact[0].span_end] == secret

    def test_no_registry_returns_empty(self):
        ctx = ExecutionContext()
        scanner = SecretsScanner()
        text = _make_text("some text with sk-fake-key-here")
        findings = scanner.scan(text, ctx)
        assert findings == []

    def test_no_match_returns_empty(self):
        registry = SecretsRegistry()
        registry.register("KEY", "very-specific-secret")
        ctx = ExecutionContext(secrets_registry=registry)
        scanner = SecretsScanner()

        text = _make_text("nothing to see here")
        findings = scanner.scan(text, ctx)
        assert len([f for f in findings if "KEY" in f.subcategory]) == 0

    def test_multiple_secrets(self):
        registry = SecretsRegistry()
        registry.register("KEY1", "secret-alpha-value-123456")
        registry.register("KEY2", "secret-beta-value-789012")
        ctx = ExecutionContext(secrets_registry=registry)
        scanner = SecretsScanner()

        text = _make_text("has secret-alpha-value-123456 and secret-beta-value-789012")
        findings = scanner.scan(text, ctx)
        names = {f.subcategory for f in findings}
        assert any("KEY1" in n for n in names)
        assert any("KEY2" in n for n in names)

    def test_scans_any_trust_level(self):
        registry = SecretsRegistry()
        registry.register("KEY", "my-secret-12345678")
        ctx = ExecutionContext(secrets_registry=registry)
        scanner = SecretsScanner()

        for trust in TrustLevel:
            text = _make_text("contains my-secret-12345678", trust=trust)
            findings = scanner.scan(text, ctx)
            assert len(findings) >= 1
