#!/usr/bin/env python3
"""Smoke test: local Guard with active span model + FP probe queries."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROBES = SDK_ROOT / "src/unplug/audit/data/fp_probe_queries.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke test Guard + span model")
    parser.add_argument("--checkpoint", type=Path, default=None)
    parser.add_argument("--probes", type=Path, default=DEFAULT_PROBES)
    parser.add_argument("--require-weights", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any false positive (including trigger_benign regex edge cases)",
    )
    args = parser.parse_args()

    from unplug.ml.validation import (
        catalog_config_from_manifest,
        resolve_validation_checkpoint,
    )

    ckpt = args.checkpoint
    if ckpt is None:
        ckpt = resolve_validation_checkpoint(require_weights=args.require_weights)
    if ckpt is None or not ckpt.is_dir():
        print("checkpoint not found: set UNPLUG_MODEL_PATH or install weights", file=sys.stderr)
        sys.exit(1)

    os.environ.setdefault("UNPLUG_ACTIVE_MODEL", "tiny")
    os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)

    from unplug import Guard
    from unplug.api.enums import Source
    from unplug.api.types import ScanRequest
    from unplug.config.loader import load

    cfg = load()
    guard = Guard(config=cfg, mode="local")
    print(f"scanners: {guard.scanners_loaded}")
    print(f"ml_loaded: {guard.ml_model_loaded}")
    print(f"checkpoint: {ckpt}")
    print(f"catalog thresholds: {catalog_config_from_manifest()}")
    print(f"model_version: {guard._model_version_for_cache()}")

    if not guard.ml_model_loaded:
        print("warning: injection_ml not loaded (weights may be missing)", file=sys.stderr)

    probes = json.loads(args.probes.read_text(encoding="utf-8"))
    fp = fn = tp = tn = 0
    everyday_fp: list[str] = []
    trigger_fp: list[str] = []
    for probe in probes:
        req = ScanRequest(text=probe["text"], source=Source.USER)
        result = guard.scan_request(req, isolated=True)
        detected = not result.safe or bool(result.findings)
        expect = bool(probe.get("expect_detected"))
        category = probe.get("category", "")
        if expect and detected:
            tp += 1
            tag = "TP"
        elif expect and not detected:
            fn += 1
            tag = "FN"
        elif not expect and detected:
            fp += 1
            tag = "FP"
            if category == "everyday":
                everyday_fp.append(probe["id"])
            elif category == "trigger_benign":
                trigger_fp.append(probe["id"])
        else:
            tn += 1
            tag = "TN"
        print(f"  [{tag}] {probe['id']}: action={result.action.value} risk={result.risk_score:.2f}")

    if trigger_fp:
        print(f"\nwarning: trigger_benign regex/ML edge FPs: {trigger_fp}", file=sys.stderr)

    if args.strict:
        ok = fp == 0 and fn == 0
    else:
        ok = fn == 0 and not everyday_fp
    print(f"\nprobes: tp={tp} fp={fp} tn={tn} fn={fn} pass={ok}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
