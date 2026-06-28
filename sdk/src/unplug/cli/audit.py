#!/usr/bin/env python3
"""CLI: unplug-audit: security wiring and optional probe batteries."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from unplug.audit.runner import run_audit


def main() -> None:
    parser = argparse.ArgumentParser(description="Unplug security audit")
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=None,
        help="Workspace root for local probe overrides (default: auto-detect)",
    )
    parser.add_argument(
        "--probes",
        action="store_true",
        help=(
            "Run probe batteries: boundary (regex OK); FP + encoding require ML "
            "(use with --require-ml or active_model=tiny)"
        ),
    )
    parser.add_argument(
        "--require-ml",
        action="store_true",
        help="Fail if ML checkpoint is not loaded",
    )
    parser.add_argument("--json", action="store_true", dest="json_out", help="Print JSON report")
    args = parser.parse_args()

    report = run_audit(
        workspace_root=args.workspace_root,
        include_probes=args.probes,
        require_ml=args.require_ml,
    )

    if args.json_out:
        print(json.dumps(report, indent=2))
    else:
        for row in report["checks"]:
            mark = "ok" if row["passed"] else "FAIL"
            print(f"[{mark}] {row['name']}: {row['detail']}")
        print(
            f"\nwiring_pass={report['wiring_pass']} "
            f"all_passed={report['all_passed']} "
            f"({report['checks_passed']}/{report['checks_total']})"
        )
        if report.get("ml_inactive_hint"):
            print(
                "\nHint: checkpoint found but ML inactive: "
                'set active_model = "tiny" or UNPLUG_ACTIVE_MODEL=tiny'
            )
        if args.probes and not args.require_ml:
            skipped = [
                row["name"]
                for row in report["checks"]
                if row["name"] in {"fp_probe_suite", "encoding_probe_suite"}
                and row["detail"].startswith("skipped")
            ]
            if skipped:
                print(
                    "\nNote: FP/encoding probes skipped without ML. "
                    "For full batteries: unplug-audit --probes --require-ml"
                )

    sys.exit(0 if report["wiring_pass"] else 1)


if __name__ == "__main__":
    main()
