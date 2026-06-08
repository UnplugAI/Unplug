"""CLI for YAML scenario replay."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.scenario_replay import load_scenario, print_replay_report, replay_scenario


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a YAML security scenario through Guard")
    parser.add_argument("scenario", type=Path, help="Path to scenario YAML file")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    args = parser.parse_args()

    if not args.scenario.exists():
        print(f"Error: scenario not found: {args.scenario}", file=sys.stderr)
        sys.exit(1)

    scenario = load_scenario(args.scenario)
    result = replay_scenario(scenario)

    if args.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_replay_report(result)

    sys.exit(0 if result.passed else 1)


if __name__ == "__main__":
    main()
