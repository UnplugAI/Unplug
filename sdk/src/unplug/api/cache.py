"""Stable scan-cache API for SDK dependents.

Import cache primitives from here instead of ``unplug.core.runtime.cache`` or the
deprecated ``unplug.core.cache`` path.
"""

from __future__ import annotations

from unplug.core.runtime.cache import (
    DEFAULT_PREFIX_OVERLAP_CHARS,
    CacheKeyParts,
    SafePrefixState,
    ScanCache,
    cache_key_parts,
    chunk_storage_key,
    effective_prefix_skip,
    merge_suffix_result,
    offset_findings,
    prefix_storage_key,
)
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION

__all__ = [
    "DEFAULT_PREFIX_OVERLAP_CHARS",
    "MODEL_VERSION_LOCAL",
    "NORMALIZER_VERSION",
    "CacheKeyParts",
    "SafePrefixState",
    "ScanCache",
    "cache_key_parts",
    "chunk_storage_key",
    "effective_prefix_skip",
    "merge_suffix_result",
    "offset_findings",
    "prefix_storage_key",
]
