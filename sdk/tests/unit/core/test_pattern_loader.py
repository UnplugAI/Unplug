"""Unit tests for pattern_loader: YAML/TOML validation and compile errors."""

from __future__ import annotations

import re

from unplug.core.pattern_loader import (
    load_compiled_patterns,
    load_pattern_entries,
    load_presidio_entity_map,
    load_privacy_label_map,
)


class TestPatternLoader:
    def test_secrets_yaml_loads(self) -> None:
        entries = load_pattern_entries("secrets.yaml")
        assert len(entries) >= 10
        assert entries[0].name

    def test_secrets_compile(self) -> None:
        patterns = load_compiled_patterns("secrets.yaml")
        assert all(isinstance(p, re.Pattern) for _, p in patterns)

    def test_presidio_map(self) -> None:
        entity_map = load_presidio_entity_map()
        assert "EMAIL_ADDRESS" in entity_map
        sub, score = entity_map["EMAIL_ADDRESS"]
        assert sub == "email_address"
        assert score > 0

    def test_privacy_labels(self) -> None:
        labels = load_privacy_label_map()
        assert labels.get("aws_key") == "secret"

    def test_injection_patterns_nonempty(self) -> None:
        patterns = load_compiled_patterns("injection.yaml")
        assert len(patterns) >= 20
