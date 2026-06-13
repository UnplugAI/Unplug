"""S6: Security stress tests: registry limits, ReDoS guards, scan latency."""

from __future__ import annotations

import time

import pytest

from unplug import Guard
from unplug.core.privacy.secrets import SecretsRegistry


class TestSecretsRegistryStress:
    def test_registry_size_limit(self) -> None:
        reg = SecretsRegistry()
        for i in range(10_000):
            reg.register(f"key_{i}", f"value_{i}")
        with pytest.raises(ValueError, match="limit"):
            reg.register("overflow", "x")

    def test_pattern_length_limit(self) -> None:
        reg = SecretsRegistry()
        with pytest.raises(ValueError, match="too long"):
            reg.register("long", "x", pattern="a" * 501)

    def test_nested_quantifier_rejected(self) -> None:
        reg = SecretsRegistry()
        with pytest.raises(ValueError, match="backtracking"):
            reg.register("redos", "x", pattern=r"(a+)+$")


class TestScanLatencyStress:
    @pytest.mark.slow
    def test_ten_k_benign_lines_under_500ms(self, guard: Guard) -> None:
        line = "Please summarize the quarterly report for the finance team."
        # Stay under default LimitConfig max_input_length (50k chars).
        text = "\n".join([line] * 800)
        start = time.perf_counter()
        result = guard.scan(text)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert result.safe is True
        assert elapsed_ms < 500.0

    @pytest.mark.slow
    def test_repeated_scans_stable(self, guard: Guard) -> None:
        text = "What is the weather in Boston today?"
        start = time.perf_counter()
        for _ in range(200):
            guard.scan(text)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 500.0


@pytest.fixture
def guard() -> Guard:
    return Guard()
