"""CLI: unplug-scan-pr — regex Guard scan on agent config files changed in a PR."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from unplug import Guard
from unplug.api.enums import Action

_SKIP_PREFIXES = (
    "sdk/tests/",
    "tests/",
    "benchmarks/",
    "docs/",
    "examples/",
    "demo/",
    ".github/",
    ".context/",
)
_AGENT_MARKERS = (
    "AGENTS.md",
    "AGENT.md",
    ".cursor/",
    "mcp.json",
    "claude_desktop_config",
    ".mcp/",
)
_MAX_CHUNK = 2000


def changed_agent_files(base_ref: str, repo_root: Path) -> list[Path]:
    """Return changed files that look like agent/MCP configuration."""
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


def scan_paths(repo_root: Path, paths: list[Path]) -> list[tuple[Path, str]]:
    """Scan files; return list of (path, message) for each blocked chunk."""
    guard = Guard()
    blocked: list[tuple[Path, str]] = []
    for path in paths:
        for chunk in _chunks(path.read_text(encoding="utf-8", errors="replace")):
            result = guard.scan(chunk, source="user")
            if result.action == Action.BLOCK or not result.safe:
                rel = path.relative_to(repo_root)
                msg = f"Unplug flagged {result.action.value} (risk={result.risk_score:.2f})"
                blocked.append((rel, msg))
                break
    return blocked


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan agent-related files changed in a PR with unplug-ai (regex-only)",
    )
    parser.add_argument("--base-ref", default="dev", help="Base branch name (default: dev)")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root (default: cwd)",
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        type=Path,
        help="Explicit file paths to scan (skips git diff when set)",
    )
    args = parser.parse_args()
    repo_root = args.repo_root.resolve()

    if args.paths:
        paths = [p if p.is_absolute() else repo_root / p for p in args.paths]
    else:
        paths = changed_agent_files(args.base_ref, repo_root)

    if not paths:
        print("No agent-related files to scan.")
        return 0

    blocked = scan_paths(repo_root, paths)
    for rel, msg in blocked:
        print(f"::error file={rel}::{msg}")
    if blocked:
        print(f"\n{len(blocked)} file(s) flagged by Unplug PR scan.")
        return 1
    print(f"Scanned {len(paths)} agent-related file(s); no issues found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
