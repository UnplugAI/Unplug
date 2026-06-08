"""Backward compatibility — use unplug.safeguards.financial."""

from __future__ import annotations

import warnings

from unplug.safeguards.financial import FinancialScanner

warnings.warn(
    "unplug.scanners.financial is deprecated, use unplug.safeguards.financial",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["FinancialScanner"]
