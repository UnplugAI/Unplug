#!/usr/bin/env python3
"""Backward-compatible wrapper for unplug.cli.scan_pr."""

from __future__ import annotations

import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from unplug.cli.scan_pr import main

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    if "--repo-root" not in sys.argv:
        sys.argv[1:1] = ["--repo-root", str(repo_root)]
    sys.exit(main())
