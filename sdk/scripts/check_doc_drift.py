#!/usr/bin/env python
"""Fail when the docs describe an API that does not exist.

Walks every ```python fence in sdk/docs/ and the repo-root markdown, collects the
`from unplug... import X` / `import unplug...` statements, and checks each one
actually resolves. Catches the case where a symbol gets renamed in code and the
docs keep the old name, which a reader only discovers by pasting the snippet and
getting an ImportError.

That only ever checked the import line. A snippet that imports fine but calls
`guard.scan(text, mode="strict")` with a kwarg that does not exist passed the
check anyway, and a reader only finds out by pasting it and getting a
TypeError. So each fence is also executed, not just import-parsed.

Fences within one file share a namespace, in file order: docs read like a
tutorial, and later snippets reuse names a preceding snippet defined (e.g. a
`guard = Guard()` a few paragraphs up). "Isolated" means isolated from other
files and from this script's own globals, not from the rest of the page.

A fence that cannot run standalone — it needs a live server, a downloaded
model, a config file on the reader's disk, or a caller-supplied object like a
LangGraph `StateGraph` — gets an HTML comment directly above it:

    <!-- doc-drift: skip-exec: needs a live unplug-server sidecar on localhost:8000 -->
    ```python
    ...
    ```

The import check still runs for a skip-exec fence; only the exec step is
skipped. Optional extras that are not installed are skipped, not failed, so
this runs the same on a minimal `uv sync --dev` as it does on a full CI
environment.

Usage: uv run python scripts/check_doc_drift.py
"""

from __future__ import annotations

import ast
import builtins
import contextlib
import importlib
import io
import re
import sys
from pathlib import Path

FENCE_RE = re.compile(
    r"(?:<!--\s*doc-drift:\s*skip-exec:?\s*(?P<reason>[^\n]*?)\s*-->\s*\n)?"
    r"```python\n(?P<code>.*?)```",
    re.DOTALL,
)
REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_GLOBS = ("sdk/docs/*.md", "*.md", "sdk/*.md", "sdk/integrations/*/README.md")

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
    executed = 0

    paths = sorted({p for g in DOC_GLOBS for p in REPO_ROOT.glob(g)})
    # A doc's snippets are a tutorial: later fences reuse names an earlier
    # fence in the same file defined. Never carry state across files.
    real_input = builtins.input
    builtins.input = lambda *_a, **_k: "n"  # never let a doc example block on stdin
    try:
        for path in paths:
            if path.name in SKIP_FILES:
                continue
            rel = path.relative_to(REPO_ROOT)
            namespace: dict[str, object] = {}
            for fence in FENCE_RE.finditer(path.read_text(encoding="utf-8")):
                code = fence.group("code")
                skip_reason = fence.group("reason")

                for module, symbol in _imports(code):
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
                        broken.append(
                            f"{rel}: importing {module} raised {type(exc).__name__}: {exc}"
                        )
                        continue

                    if symbol is None:
                        continue
                    try:
                        if not hasattr(mod, symbol):
                            broken.append(f"{rel}: {module} has no '{symbol}'")
                    except Exception:
                        # Lazy attribute that needs an extra we do not have installed.
                        skipped += 1

                if skip_reason is not None:
                    skipped += 1
                    continue

                executed += 1
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        exec(compile(code, str(rel), "exec"), namespace)
                except (ImportError, ModuleNotFoundError) as exc:
                    if _extras_missing(exc):
                        skipped += 1
                    else:
                        broken.append(f"{rel}: running snippet raised {type(exc).__name__}: {exc}")
                except SyntaxError as exc:
                    broken.append(
                        f"{rel}: snippet is not standalone Python "
                        f"(add a doc-drift: skip-exec comment if intentional): {exc}"
                    )
                except Exception as exc:
                    broken.append(f"{rel}: running snippet raised {type(exc).__name__}: {exc}")
    finally:
        builtins.input = real_input

    print(
        f"checked {checked} doc imports and executed {executed} snippets "
        f"across {len(paths)} files ({skipped} skipped: extras/marked)"
    )
    if broken:
        print("\ndocs reference APIs that do not exist, or a snippet does not run as written:")
        for line in broken:
            print(f"  {line}")
        print("\nUpdate the docs, or the symbol, so a reader can paste the snippet and run it.")
        return 1
    print("no drift")
    return 0


if __name__ == "__main__":
    sys.exit(main())
