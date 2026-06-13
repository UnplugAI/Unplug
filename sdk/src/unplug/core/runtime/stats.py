"""Metrics and statistics tracking for scanners and pipelines."""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from unplug.core.schemas.stats import PipelineStats, ScannerStats


class MetricsCollector:
    """Thread-safe metrics collection across scanners and pipelines."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scanners: dict[str, ScannerStats] = defaultdict(ScannerStats)
        self._pipelines: dict[str, PipelineStats] = defaultdict(PipelineStats)
        self._start_time = time.monotonic()

    def record_scanner(self, name: str, *, findings_count: int, latency_ms: float) -> None:
        with self._lock:
            s = self._scanners[name]
            s.scans += 1
            s.findings += findings_count
            s.total_latency_ms += latency_ms

    def record_pipeline(self, name: str, *, action: str, latency_ms: float) -> None:
        with self._lock:
            p = self._pipelines[name]
            p.runs += 1
            p.total_latency_ms += latency_ms
            if action == "block":
                p.blocked += 1
            elif action == "redact":
                p.redacted += 1
            elif action == "review":
                p.reviewed += 1
            else:
                p.allowed += 1

    def scanner_stats(self, name: str) -> ScannerStats:
        with self._lock:
            return self._scanners[name].model_copy()

    def pipeline_stats(self, name: str) -> PipelineStats:
        with self._lock:
            return self._pipelines[name].model_copy()

    def snapshot(self) -> dict:
        """Full metrics snapshot: safe to serialize."""
        with self._lock:
            uptime = time.monotonic() - self._start_time
            return {
                "uptime_seconds": round(uptime, 1),
                "scanners": {k: v.to_dict() for k, v in self._scanners.items()},
                "pipelines": {k: v.to_dict() for k, v in self._pipelines.items()},
            }

    def reset(self) -> None:
        with self._lock:
            self._scanners.clear()
            self._pipelines.clear()
            self._start_time = time.monotonic()


class _Timer:
    def __init__(self, name: str, collector: MetricsCollector | None) -> None:
        self._name = name
        self._collector = collector
        self._start = 0.0
        self.findings_count = 0

    def __enter__(self) -> _Timer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        elapsed = (time.perf_counter() - self._start) * 1000
        if self._collector is not None:
            self._collector.record_scanner(
                self._name, findings_count=self.findings_count, latency_ms=elapsed
            )


def timed_scan(name: str, collector: MetricsCollector | None = None) -> _Timer:
    """Context manager that records scanner latency + hit count."""
    return _Timer(name, collector)
