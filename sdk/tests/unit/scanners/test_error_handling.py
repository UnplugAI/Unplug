"""Tests for fail-closed error handling across the Guard stack."""

from __future__ import annotations

from collections.abc import Generator
from unittest.mock import patch

from unplug import Guard
from unplug.core.context import ExecutionContext
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Action, Finding
from unplug.scanners.base import RegexScanner


def _taint(text: str) -> TaintedText:
    return TaintedText(text=text, trust_level=TrustLevel.USER, origin="test")


class BrokenScanner(RegexScanner):
    name = "broken"
    _patterns = []

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        msg = "scanner exploded"
        raise RuntimeError(msg)


class TestScannerFailClosed:
    def test_returns_error_finding(self):
        scanner = BrokenScanner()
        result = scanner.scan(_taint("hello"), ExecutionContext())
        assert len(result) == 1
        assert result[0].category == "broken"
        assert result[0].subcategory == "scanner_error"
        assert result[0].score == 1.0
        assert "RuntimeError" in result[0].evidence

    def test_metrics_still_recorded(self):
        metrics = MetricsCollector()
        scanner = BrokenScanner(metrics=metrics)
        scanner.scan(_taint("hello"), ExecutionContext())
        snap = metrics.snapshot()
        assert snap["scanners"]["broken"]["scans"] == 1


class TestPipelineFailClosed:
    def test_pipeline_error_returns_blocked(self):
        guard = Guard(scanners=["injection"])
        with patch.object(guard._input_pipeline, "_execute", side_effect=RuntimeError("boom")):
            result = guard.scan("test input")
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.risk_score == 1.0
        assert result.findings[0].subcategory == "pipeline_error"


class TestGuardFailClosed:
    def _delayed_raise(self, *args, **kwargs):
        import time
        time.sleep(0.01)
        raise RuntimeError("fatal")

    def test_scan_error_returns_blocked(self):
        guard = Guard(scanners=["injection"])
        with patch.object(guard._input_pipeline, "run", side_effect=self._delayed_raise):
            result = guard.scan("test")
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.findings[0].subcategory == "guard_error"
        assert "RuntimeError" in result.findings[0].evidence
        assert result.stages_run == ["error"]
        assert result.latency_ms > 0.0

    def test_scan_output_error_returns_blocked(self):
        guard = Guard(scanners=["injection"])
        with patch.object(guard._output_pipeline, "run", side_effect=self._delayed_raise):
            result = guard.scan_output("test")
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.stages_run == ["error"]
        assert result.latency_ms > 0.0

    def test_check_tool_call_error_returns_blocked(self):
        guard = Guard(scanners=["injection"])
        with patch.object(guard._tool_pipeline, "run", side_effect=self._delayed_raise):
            result = guard.check_tool_call("rm", {"-rf": "/"})
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.stages_run == ["error"]
        assert result.latency_ms > 0.0
