"""Scanner protocol: deprecated, use unplug.scanners.base instead."""

from __future__ import annotations

import warnings

from unplug.scanners.base import Scanner

warnings.warn(
    "unplug.scanner is deprecated, import from unplug.scanners.base instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["Scanner"]
