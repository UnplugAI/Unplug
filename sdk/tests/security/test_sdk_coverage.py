"""SDK security coverage gate: all scanners and pipelines exercised."""

from __future__ import annotations

from benchmarks.builtin_samples import ALL_SAMPLES, FINANCIAL_TOOL_SAMPLES
from benchmarks.loader import Sample
from unplug import Guard
from unplug.api.types import ScanResult
from unplug.scanners.registry import ScannerRegistry


def _run_sample(guard: Guard, sample: Sample) -> ScanResult:
    pipeline = sample.metadata.get("pipeline", "input")
    if pipeline == "output":
        return guard.scan_output(sample.text)
    if pipeline == "toolcall":
        return guard.check_tool_call(
            str(sample.metadata.get("tool_name", "execute")),
            dict(sample.metadata.get("tool_args", {})),
        )
    return guard.scan(sample.text)


def _detected(result: ScanResult, *, threshold: float = 0.5) -> bool:
    return result.risk_score >= threshold or not result.safe


BUILTIN_SCANNERS = {
    "injection",
    "destructive",
    "leakage",
    "harmful",
    "financial",
    "secrets",
}


class TestScannerRegistry:
    def test_all_builtin_scanners_registered(self) -> None:
        available = set(ScannerRegistry.available())
        assert BUILTIN_SCANNERS.issubset(available)


class TestBuiltinBenchmark:
    def test_malicious_samples_detected(self) -> None:
        guard = Guard()
        malicious = [s for s in ALL_SAMPLES if s.label == 1]
        missed = [s for s in malicious if not _detected(_run_sample(guard, s))]
        assert not missed, [(s.category, s.text[:50]) for s in missed]

    def test_benign_samples_no_false_positives(self) -> None:
        guard = Guard()
        benign = [s for s in ALL_SAMPLES if s.label == 0 and s.category == "benign"]
        fps = [s for s in benign if _detected(_run_sample(guard, s))]
        assert not fps, [(s.category, s.text[:50]) for s in fps]


class TestToolCallCoverage:
    def test_financial_tool_samples(self) -> None:
        guard = Guard()
        for sample in FINANCIAL_TOOL_SAMPLES:
            result = _run_sample(guard, sample)
            detected = _detected(result)
            if sample.label == 1:
                assert detected, sample.text
            else:
                assert not detected, sample.text
