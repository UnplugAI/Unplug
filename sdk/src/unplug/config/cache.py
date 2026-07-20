"""Scan cache configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field

# Keep in sync with unplug.core.runtime.cache.DEFAULT_PREFIX_OVERLAP_CHARS.
_DEFAULT_PREFIX_OVERLAP_CHARS = 256


class CacheConfig(BaseModel):
    """Safe-prefix and chunk LRU settings."""

    model_config = {"frozen": True}

    enabled: bool = True
    max_chunk_entries: int = Field(default=256, ge=1)
    advance_prefix_on_redact: bool = True
    # Re-scan this many chars at the safe-prefix boundary (StreamScanner-aligned).
    prefix_overlap_chars: int = Field(default=_DEFAULT_PREFIX_OVERLAP_CHARS, ge=1)
