"""Text normalization."""

from __future__ import annotations

from unplug.core.normalize.cache import cached_normalize
from unplug.core.normalize.normalize import (
    EVASION_ONLY_STAGES,
    Normalizer,
    NormalizeResult,
)

__all__ = [
    "EVASION_ONLY_STAGES",
    "NormalizeResult",
    "Normalizer",
    "cached_normalize",
]
