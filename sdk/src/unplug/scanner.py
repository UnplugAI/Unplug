"""Scanner protocol — deprecated, use unplug.safeguards.base instead."""

from __future__ import annotations

import warnings

from unplug.safeguards.base import Scanner

warnings.warn(
    "unplug.scanner is deprecated, import from unplug.safeguards.base instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["Scanner"]
