#!/usr/bin/env python3
"""Smoke test: local Guard with active span model + FP probe queries."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CKPT = (
    ROOT
    / "repos/unplug_exp/dist/vm-v10-750k-diagnostic-bundle/"
    "experiments/unplug-tiny-v10-350k/checkpoint-24615"
)
DEFAULT_PROBES = (
    ROOT / "repos/unplug_exp/configs/fp_probe_queries.json"
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test Guard + span model")
    parser.add_argument("--checkpoint", type=Path, default=None)
    parser.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    args = parser.parse_args()

    ckpt = args.checkpoint or Path(os.environ.get("UNPLUG_MODEL_PATH", DEFAULT_CKPT))
    if not ckpt.is_dir():
        print(f"checkpoint not found: {ckpt}", file=sys.stderr)
        sys.exit(1)

    os.environ.setdefault("UNPLUG_ACTIVE_MODEL", "small")
    os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)

    from unplug import Guard
    from unplug.config.loader import load

    cfg = load()
    guard = Guard(config=cfg, mode="local")
    print(f"scanners: {guard.scanners_loaded}")
    print(f"ml_loaded: {guard.ml_model_loaded}")
    print(f"model_version: {guard._model_version_for_cache()}")  # noqa: SLF001

    probes = json.loads(args.probes.read_text(encoding="utf-8"))
    fp = fn = tp = tn = 0
    for probe in probes:
        result = guard.scan(probe["text"])
        detected = not result.safe or bool(result.findings)
        expect = bool(probe.get("expect_detected"))
        if expect and detected:
            tp += 1
            tag = "TP"
        elif expect and not detected:
            fn += 1
            tag = "FN"
        elif not expect and detected:
            fp += 1
            tag = "FP"
        else:
            tn += 1
            tag = "TN"
        print(f"  [{tag}] {probe['id']}: action={result.action.value} risk={result.risk_score:.2f}")

    print(f"\nprobes: tp={tp} fp={fp} tn={tn} fn={fn} pass={fp == 0 and fn == 0}")
    sys.exit(0 if fp == 0 and fn == 0 else 1)


if __name__ == "__main__":
    main()
