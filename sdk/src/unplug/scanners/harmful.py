"""Backward compatibility — use unplug.safeguards.harmful."""

from __future__ import annotations

import warnings

from unplug.safeguards.harmful import HarmfulScanner

warnings.warn(
    "unplug.scanners.harmful is deprecated, use unplug.safeguards.harmful",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["HarmfulScanner"]
