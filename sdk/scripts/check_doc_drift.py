#!/usr/bin/env python
"""Fail when the docs describe an API that does not exist.

Walks every ```python fence in docs/ and the repo-root markdown, collects the
`from unplug... import X` / `import unplug...` statements, and checks each one
actually resolves. Catches the case where a symbol gets renamed in code and the
docs keep the old name, which a reader only discovers by pasting the snippet and
getting an ImportError.

Optional extras that are not installed are skipped, not failed, so this runs the
same on a minimal `uv sync --dev` as it does on a full CI environment.

Usage: uv run python scripts/check_doc_drift.py
"""

from __future__ import annotations

import ast
import importlib
import re
import sys
from pathlib import Path

FENCE_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)
REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_GLOBS = ("docs/*.md", "*.md", "sdk/*.md", "sdk/integrations/*/README.md")

# The docs deliberately reference the old name in these files.
SKIP_FILES = {"MIGRATION.md", "CHANGELOG.md"}


def _extras_missing(exc: BaseException) -> bool:
    text = str(exc)
    return "requires the extra" in text or (
        isinstance(exc, ModuleNotFoundError) and not text.startswith("No module named 'unplug")
    )


def _imports(source: str) -> list[tuple[str, str | None]]:
    """Return (module, symbol) pairs for unplug imports in one code fence."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    found: list[tuple[str, str | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "unplug":
                found.extend((node.module, alias.name) for alias in node.names)
        elif isinstance(node, ast.Import):
            found.extend(
                (alias.name, None) for alias in node.names if alias.name.split(".")[0] == "unplug"
            )
    return found


def main() -> int:
    broken: list[str] = []
    skipped = 0
    checked = 0

    paths = sorted({p for g in DOC_GLOBS for p in REPO_ROOT.glob(g)})
    for path in paths:
        if path.name in SKIP_FILES:
            continue
        rel = path.relative_to(REPO_ROOT)
        for fence in FENCE_RE.findall(path.read_text(encoding="utf-8")):
            for module, symbol in _imports(fence):
                checked += 1
                try:
                    mod = importlib.import_module(module)
                except ImportError as exc:
                    if _extras_missing(exc):
                        skipped += 1
                        continue
                    broken.append(f"{rel}: cannot import {module} ({exc})")
                    continue
                except Exception as exc:
                    # Report and keep going; one bad module should not hide the rest.
                    broken.append(f"{rel}: importing {module} raised {type(exc).__name__}: {exc}")
                    continue

                if symbol is None:
                    continue
                try:
                    if not hasattr(mod, symbol):
                        broken.append(f"{rel}: {module} has no '{symbol}'")
                except Exception:
                    # Lazy attribute that needs an extra we do not have installed.
                    skipped += 1

    print(f"checked {checked} doc imports across {len(paths)} files ({skipped} skipped: extras)")
    if broken:
        print("\ndocs reference APIs that do not exist:")
        for line in broken:
            print(f"  {line}")
        print("\nUpdate the docs, or the symbol, so a reader can paste the snippet and run it.")
        return 1
    print("no drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
