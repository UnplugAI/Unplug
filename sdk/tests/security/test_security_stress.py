"""S6: Security stress tests: registry limits, ReDoS guards, scan latency.

Policy for the wall-clock assertions below (issue #144):

* These tests are marked `slow` and are deselected from the default/PR gate
  (pyproject.toml addopts). They run nightly / on manual dispatch via
  .github/workflows/slow-stress.yml, and locally via `make test-slow`.
* Absolute time budgets mean different things on different machines — the
  benign-lines scan has been observed from ~250 ms (fast laptop) to ~2.2 s
  (loaded Windows dev box) with the same code — so the numbers are
  deliberately loose. They exist to catch order-of-magnitude regressions
  (e.g. accidentally superlinear scan behaviour), not normal variance.
* The two budgets are paired and must move TOGETHER: if one needs to change,
  change both and update this comment. Do not "fix" a flake by nudging a
  number — if these fail on a runner, the scan has genuinely regressed or
  the `not slow` deselect fell off the gate.
"""

from __future__ import annotations

import time

import pytest

from unplug import Guard
from unplug.core.privacy.secrets import SecretsRegistry

# Loose by design — see the policy note at the top of this file.
SCAN_LATENCY_BUDGET_MS = 5000.0


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
    def test_ten_k_benign_lines_scan_latency(self, guard: Guard) -> None:
        line = "Please summarize the quarterly report for the finance team."
        # Stay under default LimitConfig max_input_length (50k chars).
        text = "\n".join([line] * 800)
        start = time.perf_counter()
        result = guard.scan(text)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert result.safe is True
        assert elapsed_ms < SCAN_LATENCY_BUDGET_MS

    @pytest.mark.slow
    def test_repeated_scans_stable(self, guard: Guard) -> None:
        text = "What is the weather in Boston today?"
        start = time.perf_counter()
        for _ in range(200):
            guard.scan(text)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < SCAN_LATENCY_BUDGET_MS


@pytest.fixture
def guard() -> Guard:
    return Guard()
