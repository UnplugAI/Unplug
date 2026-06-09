"""Backward compatibility — use unplug.safeguards.leakage."""

from __future__ import annotations

import warnings

from unplug.safeguards.leakage import LEAKAGE_PATTERNS, LeakageScanner

warnings.warn(
    "unplug.scanners.leakage is deprecated, use unplug.safeguards.leakage",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["LEAKAGE_PATTERNS", "LeakageScanner"]
