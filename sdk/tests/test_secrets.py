"""Tests for core/secrets.py — SecretsRegistry, SecretsSanitizer."""

import os
from unittest.mock import patch

import pytest

from unplug.core.secrets import SecretEntry, SecretsRegistry, SecretsSanitizer


class TestSecretEntry:
    def test_repr_hides_value(self):
        entry = SecretEntry(name="API_KEY", value="super-secret-123", source="env")
        r = repr(entry)
        assert "super-secret-123" not in r
        assert "API_KEY" in r

    def test_str_hides_value(self):
        entry = SecretEntry(name="API_KEY", value="super-secret-123", source="env")
        assert "super-secret-123" not in str(entry)

    def test_model_dump_excludes_value(self):
        entry = SecretEntry(name="API_KEY", value="super-secret-123", source="env")
        dumped = entry.model_dump()
        assert "value" not in dumped
        assert "pattern" not in dumped

    def test_json_excludes_value(self):
        entry = SecretEntry(name="API_KEY", value="super-secret-123", source="env")
        json_str = entry.model_dump_json()
        assert "super-secret-123" not in json_str


class TestSecretsRegistry:
    def test_register_and_contains(self):
        reg = SecretsRegistry()
        reg.register("MY_KEY", "sk-abc123def456ghi789")
        matches = reg.contains("Here is my key: sk-abc123def456ghi789 ok?")
        assert len(matches) >= 1
        assert matches[0].secret_name == "MY_KEY"
        assert matches[0].source == "registry_exact_match"

    def test_contains_with_spans(self):
        reg = SecretsRegistry()
        reg.register("TOKEN", "secret_token_value")
        text = "prefix secret_token_value suffix"
        matches = reg.contains(text)
        exact = [m for m in matches if m.source == "registry_exact_match"]
        assert len(exact) == 1
        assert text[exact[0].span_start : exact[0].span_end] == "secret_token_value"

    def test_contains_multiple_occurrences(self):
        reg = SecretsRegistry()
        reg.register("KEY", "abc")
        matches = reg.contains("abc and abc again")
        exact = [m for m in matches if m.source == "registry_exact_match"]
        assert len(exact) == 2

    def test_contains_no_match(self):
        reg = SecretsRegistry()
        reg.register("KEY", "secret123")
        matches = reg.contains("nothing here")
        assert len([m for m in matches if m.source == "registry_exact_match"]) == 0

    def test_register_empty_value_ignored(self):
        reg = SecretsRegistry()
        reg.register("EMPTY", "")
        assert len(reg._secrets) == 0

    def test_register_with_pattern(self):
        reg = SecretsRegistry()
        reg.register("CUSTOM", "exact-val", pattern=r"custom-\d+")
        matches = reg.contains("found custom-12345 here")
        pattern_matches = [m for m in matches if m.source == "pattern_match"]
        assert len(pattern_matches) == 1

    def test_register_from_env(self):
        env = {"OPENAI_API_KEY": "sk-test123", "AWS_SECRET": "aws-val", "UNRELATED": "val"}
        with patch.dict(os.environ, env, clear=True):
            reg = SecretsRegistry()
            count = reg.register_from_env(["OPENAI_", "AWS_"])
        assert count == 2
        assert "OPENAI_API_KEY" in reg._secrets
        assert "AWS_SECRET" in reg._secrets
        assert "UNRELATED" not in reg._secrets

    def test_register_from_env_skips_empty(self):
        env = {"OPENAI_KEY": ""}
        with patch.dict(os.environ, env, clear=True):
            reg = SecretsRegistry()
            count = reg.register_from_env(["OPENAI_"])
        assert count == 0

    def test_redact(self):
        reg = SecretsRegistry()
        reg.register("KEY1", "secret1")
        reg.register("KEY2", "secret2")
        result = reg.redact("has secret1 and secret2 inside")
        assert "secret1" not in result
        assert "secret2" not in result
        assert "[REDACTED:KEY1]" in result
        assert "[REDACTED:KEY2]" in result

    def test_redact_longest_first(self):
        reg = SecretsRegistry()
        reg.register("SHORT", "abc")
        reg.register("LONG", "abcdef")
        result = reg.redact("contains abcdef here")
        assert "[REDACTED:LONG]" in result
        assert "[REDACTED:SHORT]" not in result

    def test_generic_pattern_fallback(self):
        reg = SecretsRegistry()
        matches = reg.contains("key is AKIA1234567890123456")
        generic = [m for m in matches if m.source == "generic_pattern"]
        assert len(generic) >= 1

    def test_generic_pattern_not_duplicate_with_exact(self):
        reg = SecretsRegistry()
        reg.register("AWS", "AKIA1234567890123456")
        matches = reg.contains("key is AKIA1234567890123456")
        exact = [m for m in matches if m.source == "registry_exact_match"]
        generic = [m for m in matches if m.source == "generic_pattern"]
        assert len(exact) == 1
        assert len(generic) == 0


class TestSecretsSanitizer:
    def test_sanitize(self):
        reg = SecretsRegistry()
        reg.register("MY_SECRET", "super-secret-value")
        sanitizer = SecretsSanitizer(reg)
        result = sanitizer.sanitize("The value is super-secret-value please")
        assert "super-secret-value" not in result.clean_text
        assert len(result.secrets_found) >= 1

    def test_sanitize_no_secrets(self):
        reg = SecretsRegistry()
        sanitizer = SecretsSanitizer(reg)
        result = sanitizer.sanitize("just normal text")
        assert result.clean_text == "just normal text"
        assert result.secrets_found == []

    def test_sanitize_multiple_generic_patterns(self):
        reg = SecretsRegistry()
        sanitizer = SecretsSanitizer(reg)
        text = "keys sk-abcdefghijklmnopqrstuvwxyz123456 and sk-zyxwvutsrqponmlkjihgfedcba654321"
        result = sanitizer.sanitize(text)
        assert "sk-" not in result.clean_text
        assert result.clean_text.count("[REDACTED]") >= 2

    def test_sanitize_overlapping_generic_spans(self):
        reg = SecretsRegistry()
        sanitizer = SecretsSanitizer(reg)
        text = "export api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
        result = sanitizer.sanitize(text)
        assert "sk-" not in result.clean_text
        assert "api_key=" not in result.clean_text
        assert "[REDACTED]" in result.clean_text

    def test_register_redos_pattern_rejected(self):
        reg = SecretsRegistry()
        with pytest.raises(ValueError, match="backtracking"):
            reg.register("BAD", "x", pattern=r"(a+)+$")

    def test_register_invalid_pattern(self):
        reg = SecretsRegistry()
        with pytest.raises(ValueError, match="Invalid regex"):
            reg.register("BAD", "x", pattern=r"[unclosed")
