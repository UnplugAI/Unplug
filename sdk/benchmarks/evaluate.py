"""Evaluation runner: measures scanner performance against labeled datasets."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from benchmarks.loader import Sample
from unplug import Guard
from unplug.models import ScanResult


@dataclass
class CategoryMetrics:
    """Precision/recall/F1 for a single category."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    total_latency_ms: float = 0.0
    samples: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.samples if self.samples else 0.0

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fpr": round(self.false_positive_rate, 4),
            "tp": self.true_positives,
            "fp": self.false_positives,
            "fn": self.false_negatives,
            "tn": self.true_negatives,
            "samples": self.samples,
            "avg_latency_ms": round(self.avg_latency_ms, 3),
        }


@dataclass
class EvalResult:
    """Full evaluation results across all categories."""

    overall: CategoryMetrics = field(default_factory=CategoryMetrics)
    by_category: dict[str, CategoryMetrics] = field(default_factory=dict)
    total_samples: int = 0
    total_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "overall": self.overall.to_dict(),
            "by_category": {k: v.to_dict() for k, v in self.by_category.items()},
            "total_samples": self.total_samples,
            "total_time_ms": round(self.total_time_ms, 1),
        }


def _default_guard_factory() -> Guard:
    return Guard()


def run_sample(guard: Guard, sample: Sample) -> ScanResult:
    """Route a sample to the correct Guard pipeline based on metadata."""
    pipeline = sample.metadata.get("pipeline", "input")
    if pipeline == "output":
        return guard.scan_output(sample.text)
    if pipeline == "toolcall":
        tool_name = sample.metadata.get("tool_name", "unknown")
        tool_args = sample.metadata.get("tool_args", {"cmd": sample.text})
        agent_id = sample.metadata.get("agent_id")
        if agent_id:
            guard.context.agent_id = str(agent_id)
        return guard.check_tool_call(tool_name, tool_args)
    return guard.scan(sample.text)


def evaluate(
    samples: list[Sample],
    guard: Guard | None = None,
    threshold: float = 0.5,
    *,
    isolate_sessions: bool = True,
    guard_factory: Callable[[], Guard] | None = None,
) -> EvalResult:
    """Run all samples through the Guard and compute metrics.

    Args:
        samples: Labeled evaluation samples.
        guard: Guard instance to test when ``isolate_sessions`` is False.
        threshold: Risk score threshold for considering a scan "detected".
        isolate_sessions: When True (default), use a fresh Guard per sample so
            trajectory/crescendo state does not bleed across the dataset.
        guard_factory: Callable returning a new Guard; used when
            ``isolate_sessions`` is True. Defaults to ``Guard()``.
    """
    factory = guard_factory or _default_guard_factory
    shared = None if isolate_sessions else (guard or factory())

    result = EvalResult()
    start = time.perf_counter()

    for sample in samples:
        result.total_samples += 1
        cat = sample.category

        if cat not in result.by_category:
            result.by_category[cat] = CategoryMetrics()
        cat_metrics = result.by_category[cat]

        active = factory() if isolate_sessions else shared
        assert active is not None

        scan_start = time.perf_counter()
        scan_result = run_sample(active, sample)
        latency = (time.perf_counter() - scan_start) * 1000

        detected = scan_result.risk_score >= threshold
        is_malicious = sample.label == 1

        cat_metrics.samples += 1
        cat_metrics.total_latency_ms += latency
        result.overall.samples += 1
        result.overall.total_latency_ms += latency

        if is_malicious and detected:
            cat_metrics.true_positives += 1
            result.overall.true_positives += 1
        elif is_malicious and not detected:
            cat_metrics.false_negatives += 1
            result.overall.false_negatives += 1
        elif not is_malicious and detected:
            cat_metrics.false_positives += 1
            result.overall.false_positives += 1
        else:
            cat_metrics.true_negatives += 1
            result.overall.true_negatives += 1

    result.total_time_ms = (time.perf_counter() - start) * 1000
    return result


def print_report(result: EvalResult) -> None:
    """Print a formatted evaluation report."""
    print("\n" + "=" * 72)
    print("EVALUATION REPORT")
    print("=" * 72)

    o = result.overall
    print(f"\nOverall ({result.total_samples} samples, {result.total_time_ms:.0f}ms)")
    print(f"  Precision: {o.precision:.4f}")
    print(f"  Recall:    {o.recall:.4f}")
    print(f"  F1:        {o.f1:.4f}")
    print(f"  FPR:       {o.false_positive_rate:.4f}")
    print(f"  Latency:   {o.avg_latency_ms:.2f}ms avg")

    if result.by_category:
        print(f"\n{'Category':<25} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6} {'N':>5}")
        print("-" * 56)
        for name, m in sorted(result.by_category.items()):
            print(
                f"{name:<25} {m.precision:>6.3f} {m.recall:>6.3f}"
                f" {m.f1:>6.3f} {m.false_positive_rate:>6.3f} {m.samples:>5}"
            )

    print("=" * 72)
