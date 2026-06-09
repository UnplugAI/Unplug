"""Backward compatibility — use unplug.safeguards.secrets."""

from __future__ import annotations

import warnings

from unplug.safeguards.secrets import SecretsScanner

warnings.warn(
    "unplug.scanners.secrets is deprecated, use unplug.safeguards.secrets",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["SecretsScanner"]
