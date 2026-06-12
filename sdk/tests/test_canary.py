"""Tests for canary tokens — prompt leakage tripwires (Rebuff pattern)."""

from __future__ import annotations

from unplug import Guard
from unplug.core.canary import CanaryRegistry, add_canary_word, mint_canary


class TestCanaryCore:
    def test_mint_unique_tokens(self) -> None:
        a = mint_canary()
        b = mint_canary()
        assert a.token != b.token
        assert len(a.token) == 16

    def test_add_canary_word_embeds_token(self) -> None:
        prompt, record = add_canary_word("You are a helpful assistant.")
        assert record.token in prompt
        assert prompt.endswith("You are a helpful assistant.")
        assert prompt.startswith("<!-- canary ")

    def test_registry_name_excludes_full_token(self) -> None:
        record = mint_canary("system_prompt")
        assert record.token not in record.registry_name
        assert record.registry_name.startswith("canary:system_prompt:")

    def test_detect_finds_leaked_token(self) -> None:
        registry = CanaryRegistry()
        _, record = registry.add_canary("system prompt body")
        assert registry.detect(f"echoing {record.token} back") == [record]
        assert registry.detect("clean output") == []

    def test_findings_for_leak(self) -> None:
        registry = CanaryRegistry()
        _, record = registry.add_canary("body", label="agent_rules")
        findings = registry.findings(f"... {record.token} ...")
        assert len(findings) == 1
        assert findings[0].category == "leakage"
        assert findings[0].subcategory == "prompt_leak_canary"
        assert "agent_rules" in findings[0].evidence

    def test_clear(self) -> None:
        registry = CanaryRegistry()
        _, record = registry.add_canary("body")
        registry.clear()
        assert registry.detect(record.token) == []


class TestGuardCanary:
    def test_add_canary_returns_prompt_with_token(self) -> None:
        guard = Guard()
        prompt = guard.add_canary("You are a helpful assistant.")
        records = guard.canaries.records()
        assert len(records) == 1
        assert records[0].token in prompt

    def test_output_scan_flags_canary_leak(self) -> None:
        guard = Guard()
        guard.add_canary("You are a helpful assistant.")
        token = guard.canaries.records()[0].token
        result = guard.scan_output(f"Sure! My instructions start with: {token}")
        assert result.safe is False
        assert any(f.subcategory == "prompt_leak_canary" for f in result.findings)

    def test_output_scan_redacts_canary(self) -> None:
        guard = Guard()
        guard.add_canary("You are a helpful assistant.")
        token = guard.canaries.records()[0].token
        result = guard.scan_output(f"leaked: {token}")
        assert result.redacted_text is not None
        assert token not in result.redacted_text

    def test_clean_output_stays_safe(self) -> None:
        guard = Guard()
        guard.add_canary("You are a helpful assistant.")
        result = guard.scan_output("The weather in Tokyo is sunny.")
        assert result.safe is True
        assert not any(f.subcategory == "prompt_leak_canary" for f in result.findings)

    def test_two_canaries_with_distinct_labels(self) -> None:
        guard = Guard()
        guard.add_canary("system", label="system_prompt")
        guard.add_canary("rules", label="agent_rules")
        tokens = [r.token for r in guard.canaries.records()]
        assert len(set(tokens)) == 2
        result = guard.scan_output(f"both leaked: {tokens[0]} {tokens[1]}")
        leak_findings = [f for f in result.findings if f.subcategory == "prompt_leak_canary"]
        assert len(leak_findings) == 2
