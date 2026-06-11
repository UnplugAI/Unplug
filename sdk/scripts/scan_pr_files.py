#!/usr/bin/env python3
"""Scan changed files in a PR for prompt injection patterns (regex-only Guard)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from unplug import Guard
from unplug.api.enums import Action

_SKIP_PREFIXES = (
    "sdk/tests/",
    "sdk/benchmarks/",
    "sdk/docs/",
    "sdk/examples/",
    "sdk/demo/",
    ".github/",
    ".context/",
)
_AGENT_MARKERS = ("AGENTS.md", ".cursor/", "mcp.json", "claude_desktop_config")
_MAX_CHUNK = 2000


def _changed_files(base_ref: str, repo_root: Path) -> list[Path]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"origin/{base_ref}...HEAD"],
        cwd=repo_root,
        text=True,
    )
    paths: list[Path] = []
    for line in out.splitlines():
        rel = line.strip()
        if not rel or any(rel.startswith(p) for p in _SKIP_PREFIXES):
            continue
        path = repo_root / rel
        if not path.is_file():
            continue
        rel_posix = rel.replace("\\", "/")
        if any(marker in rel_posix for marker in _AGENT_MARKERS):
            paths.append(path)
    return paths


def _chunks(text: str) -> list[str]:
    text = text[:50_000]
    return [text[i : i + _MAX_CHUNK] for i in range(0, len(text), _MAX_CHUNK)] or [text]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-ref", default="main")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()

    guard = Guard()
    blocked = 0
    for path in _changed_files(args.base_ref, args.repo_root):
        rel = path.relative_to(args.repo_root)
        for chunk in _chunks(path.read_text(encoding="utf-8", errors="replace")):
            result = guard.scan(chunk, source="user")
            if result.action == Action.BLOCK or not result.safe:
                msg = f"Unplug flagged {result.action.value} (risk={result.risk_score:.2f})"
                print(f"::error file={rel}::{msg}")
                blocked += 1
                break
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
