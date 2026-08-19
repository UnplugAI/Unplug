"""CLI runner for dataset evaluation.

Usage:
    uv run python -m benchmarks.run <dataset_path> [--threshold 0.5] [--format json]
    uv run python -m benchmarks.run data/neuralchemy.parquet
    uv run python -m benchmarks.run data/attacks.jsonl --threshold 0.3 --format json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.evaluate import evaluate, print_report
from benchmarks.loader import load_auto


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Unplug scanners against a dataset")
    parser.add_argument("dataset", type=Path, help="Path to dataset (JSONL, CSV, or Parquet)")
    parser.add_argument(
        "--threshold", type=float, default=0.5, help="Risk score threshold (default: 0.5)"
    )
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--text-col", default="text", help="Column name for text")
    parser.add_argument("--label-col", default="label", help="Column name for label")
    parser.add_argument("--category-col", default="category", help="Column name for category")
    parser.add_argument("--limit", type=int, default=None, help="Max samples to evaluate")
    parser.add_argument(
        "--ml",
        action="store_true",
        help="Use Guard(model='tiny') (ML second-pass) instead of regex-only",
    )
    parser.add_argument(
        "--isolated",
        action="store_true",
        help="Scan each sample in a fresh context (single-turn; no trajectory leakage)",
    )

    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"Error: dataset not found: {args.dataset}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading {args.dataset}...", file=sys.stderr)
    samples = load_auto(
        args.dataset,
        text_col=args.text_col,
        label_col=args.label_col,
        category_col=args.category_col,
    )

    if args.limit:
        samples = samples[: args.limit]

    # ML reuses one loaded guard with a fresh context per sample. A per-sample
    # guard rebuild would reload the model every time, so --ml implies isolated
    # request mode -- this also prevents silently falling back to a regex-only
    # Guard() (which would report regex numbers under an --ml run).
    isolated = args.isolated or args.ml

    guard = None
    if args.ml:
        from unplug import Guard

        print('Loading Guard(model="tiny") (ML)...', file=sys.stderr)
        guard = Guard(model="tiny", require_ml=True)

    print(
        f"Evaluating {len(samples)} samples (threshold={args.threshold}, ml={args.ml}, "
        f"isolated={isolated})...",
        file=sys.stderr,
    )
    result = evaluate(
        samples,
        guard=guard,
        threshold=args.threshold,
        isolated_requests=isolated,
        isolate_sessions=not isolated,
    )

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result)


if __name__ == "__main__":
    main()
