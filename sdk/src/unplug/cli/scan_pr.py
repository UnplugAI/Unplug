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
    ".context/",
)
_AGENT_MARKERS = (
    "AGENTS.md",
    "AGENT.md",
    ".cursor/",
    "mcp.json",
    "claude_desktop_config",
    ".mcp/",
    "copilot-instructions",
    ".github/agents/",
)
_MAX_CHUNK = 2000
_CHUNK_OVERLAP = 200


def _is_agent_file(rel: str) -> bool:
    """True if a repo-relative path looks like in-scope agent/MCP configuration."""
    if not rel or any(rel.startswith(p) for p in _SKIP_PREFIXES):
        return False
    rel_posix = rel.replace("\\", "/")
    return any(marker in rel_posix for marker in _AGENT_MARKERS)


def base_ref_exists(base_ref: str, repo_root: Path) -> bool:
    """True if origin/<base_ref> resolves to a commit (needs a fetch-depth: 0 checkout)."""
    result = subprocess.run(  # noqa: S603
        ["git", "rev-parse", "--verify", "--quiet", f"origin/{base_ref}^{{commit}}"],  # noqa: S607
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def changed_agent_files(base_ref: str, repo_root: Path) -> list[Path]:
    """Return changed files that look like agent/MCP configuration."""
    # Fixed git argv (no shell); base_ref is passed as a list element, not interpolated
    # into a shell string, so there is no command-injection surface.
    out = subprocess.check_output(  # noqa: S603
        ["git", "diff", "--name-only", "--diff-filter=ACMRT", f"origin/{base_ref}...HEAD"],  # noqa: S607
        cwd=repo_root,
        text=True,
    )
    paths: list[Path] = []
    for line in out.splitlines():
        rel = line.strip()
        if not _is_agent_file(rel):
            continue
        path = repo_root / rel
        if not path.is_file():
            continue
        paths.append(path)
    return paths


def _chunks(text: str) -> list[str]:
    """Overlapping windows so an injection straddling a chunk boundary is still
    wholly contained in at least one chunk."""
    text = text[:50_000]
    if len(text) <= _MAX_CHUNK:
        return [text]
    step = _MAX_CHUNK - _CHUNK_OVERLAP
    return [text[i : i + _MAX_CHUNK] for i in range(0, len(text), step)]


def scan_paths(repo_root: Path, paths: list[Path]) -> list[tuple[Path, str]]:
    """Scan files; return list of (path, message) for each blocked chunk."""
    guard = Guard()
    blocked: list[tuple[Path, str]] = []
    for path in paths:
        for chunk in _chunks(path.read_text(encoding="utf-8", errors="replace")):
            result = guard.scan(chunk, source="user")
            if result.action == Action.BLOCK or not result.safe:
                try:
                    rel = path.relative_to(repo_root)
                except ValueError:
                    rel = path
                msg = f"Unplug flagged {result.action.value} (risk={result.risk_score:.2f})"
                blocked.append((rel, msg))
                break
    return blocked


def main_argv(argv: list[str] | None = None) -> int:
    """Run the scan with an explicit argv (testable entry point)."""
    parser = argparse.ArgumentParser(
        description="Scan agent-related files changed in a PR with unplug-ai (regex-only)",
    )
    parser.add_argument("--base-ref", default="main", help="Base branch name (default: main)")
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
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()

    if args.paths:
        paths = [p if p.is_absolute() else repo_root / p for p in args.paths]
    elif not base_ref_exists(args.base_ref, repo_root):
        print(
            f"::error::Base ref 'origin/{args.base_ref}' not found. Check out with full history "
            "(fetch-depth: 0) and pass the correct --base-ref; refusing to scan a possibly-empty "
            "diff."
        )
        return 2
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


def main() -> int:
    return main_argv()


if __name__ == "__main__":
    sys.exit(main())
