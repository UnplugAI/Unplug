"""Stable text-normalization API for SDK dependents.

Import normalizers from here instead of ``unplug.core.normalize``.
"""

from __future__ import annotations

from unplug.core.normalize import (
    EVASION_ONLY_STAGES,
    Normalizer,
    NormalizeResult,
    cached_normalize,
)

__all__ = [
    "EVASION_ONLY_STAGES",
    "NormalizeResult",
    "Normalizer",
    "cached_normalize",
]
