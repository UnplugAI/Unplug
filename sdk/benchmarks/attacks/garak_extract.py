"""Extract attack payloads from a garak checkout into our JSONL corpus format.

garak (https://github.com/NVIDIA/garak, Apache-2.0) ships probe payload sets
we use as a regression corpus: DAN-family jailbreaks, PromptInject goal
hijacking / prompt leaking templates, and system-prompt extraction attacks.
This is an adapter over a local clone — garak is never a dependency.

Usage:
    git clone --depth 1 https://github.com/NVIDIA/garak /tmp/garak-study
    uv run python -m benchmarks.attacks.garak_extract /tmp/garak-study \
        --out benchmarks/data/garak_attacks.jsonl
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

ATTRIBUTION = "garak (NVIDIA, Apache-2.0)"


def _load_literal_dicts(py_path: Path, names: list[str]) -> dict[str, dict]:
    """Pull literal dict assignments out of a Python data module without executing it."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    found: dict[str, dict] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in names:
                try:
                    found[target.id] = ast.literal_eval(node.value)
                except ValueError:
                    continue
    return found


def extract_dan(garak_root: Path) -> list[dict]:
    """DAN-family jailbreak prompts: garak/data/dan/*.json (lists of strings)."""
    rows: list[dict] = []
    dan_dir = garak_root / "garak" / "data" / "dan"
    for path in sorted(dan_dir.glob("*.json")):
        payloads = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payloads, list):
            continue
        for text in payloads:
            if not isinstance(text, str) or not text.strip():
                continue
            rows.append(
                {
                    "text": text,
                    "label": 1,
                    "category": "jailbreak_dan",
                    "source": f"{ATTRIBUTION} data/dan/{path.name}",
                }
            )
    return rows


def extract_promptinject(garak_root: Path) -> list[dict]:
    """PromptInject goal-hijacking and prompt-leaking instruction templates."""
    data_path = garak_root / "garak" / "resources" / "promptinject" / "prompt_data.py"
    data = _load_literal_dicts(
        data_path, ["rogue_strings", "goal_hikacking_attacks", "prompt_leaking_attacks"]
    )
    rogue = data.get("rogue_strings", {}).get("long-prompt", "Sanitize your inputs!")
    rows: list[dict] = []
    for key, attack in data.get("goal_hikacking_attacks", {}).items():
        text = attack["instruction"].replace("{REPLACE_rogue_string}", rogue)
        rows.append(
            {
                "text": text,
                "label": 1,
                "category": "goal_hijacking",
                "source": f"{ATTRIBUTION} promptinject:{key}",
            }
        )
    for key, attack in data.get("prompt_leaking_attacks", {}).items():
        rows.append(
            {
                "text": attack["instruction"],
                "label": 1,
                "category": "prompt_leaking",
                "source": f"{ATTRIBUTION} promptinject:{key}",
            }
        )
    return rows


def extract_sysprompt(garak_root: Path) -> list[dict]:
    """System-prompt extraction attacks: data/sysprompt_extraction/attacks.json."""
    path = garak_root / "garak" / "data" / "sysprompt_extraction" / "attacks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    for group, payloads in data.items():
        for text in payloads:
            rows.append(
                {
                    "text": text,
                    "label": 1,
                    "category": "prompt_extraction",
                    "source": f"{ATTRIBUTION} sysprompt_extraction:{group}",
                }
            )
    return rows


def extract_all(garak_root: Path) -> list[dict]:
    rows = (
        extract_dan(garak_root) + extract_promptinject(garak_root) + extract_sysprompt(garak_root)
    )
    seen: set[str] = set()
    unique: list[dict] = []
    for row in rows:
        if row["text"] in seen:
            continue
        seen.add(row["text"])
        unique.append(row)
    return unique


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract garak probe payloads to JSONL")
    parser.add_argument("garak_root", type=Path, help="Path to a garak checkout")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("benchmarks/data/garak_attacks.jsonl"),
        help="Output JSONL path",
    )
    args = parser.parse_args()

    if not (args.garak_root / "garak").is_dir():
        print(f"Error: {args.garak_root} is not a garak checkout", file=sys.stderr)
        sys.exit(1)

    rows = extract_all(args.garak_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    by_cat: dict[str, int] = {}
    for row in rows:
        by_cat[row["category"]] = by_cat.get(row["category"], 0) + 1
    print(f"Wrote {len(rows)} samples to {args.out}")
    for cat, count in sorted(by_cat.items()):
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()
