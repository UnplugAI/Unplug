"""Backward compatibility — use unplug.safeguards.destructive."""

from __future__ import annotations

import warnings

from unplug.safeguards.destructive import DestructiveScanner

warnings.warn(
    "unplug.scanners.destructive is deprecated, use unplug.safeguards.destructive",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["DestructiveScanner"]
