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
# Whole files are scanned in a single pass (Guard's default input limit is 50k
# chars). We deliberately do NOT window the text: any fixed-size chunk boundary
# can split a prompt-injection phrase so neither chunk matches it, letting a
# crafted agent file scan clean. The cap is only a DoS guard for huge files.
_MAX_SCAN_CHARS = 50_000


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


def _scannable_text(text: str) -> str:
    """Cap pathologically large files; the file is scanned whole (no windowing)."""
    return text[:_MAX_SCAN_CHARS]


def scan_paths(repo_root: Path, paths: list[Path]) -> list[tuple[Path, str]]:
    """Scan files whole; return list of (path, message) for each blocked file."""
    guard = Guard()
    blocked: list[tuple[Path, str]] = []
    for path in paths:
        text = _scannable_text(path.read_text(encoding="utf-8", errors="replace"))
        result = guard.scan(text, source="user")
        if result.action == Action.BLOCK or not result.safe:
            try:
                rel = path.relative_to(repo_root)
            except ValueError:
                rel = path
            msg = f"Unplug flagged {result.action.value} (risk={result.risk_score:.2f})"
            blocked.append((rel, msg))
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
