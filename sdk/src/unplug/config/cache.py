"""Scan cache configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

# Keep in sync with unplug.core.runtime.cache.DEFAULT_PREFIX_OVERLAP_CHARS.
_DEFAULT_PREFIX_OVERLAP_CHARS = 256


class CacheConfig(BaseModel):
    """Safe-prefix and chunk LRU settings."""

    model_config = {"frozen": True}

    enabled: bool = True
    max_chunk_entries: int = Field(default=256, ge=1)
    advance_prefix_on_redact: bool = Field(
        default=True,
        deprecated=True,
    )
    # Characters to re-scan at the safe-prefix boundary (StreamScanner-aligned).
    # The required minimum is 256 for split-injection detection.  Lower values
    # are accepted only when allow_unsafe_overlap=True, because they reduce
    # boundary coverage for encoded and split-boundary payloads.
    prefix_overlap_chars: int = Field(
        default=_DEFAULT_PREFIX_OVERLAP_CHARS,
        ge=0,
    )
    allow_unsafe_overlap: bool = Field(
        default=False,
        description="Allow prefix_overlap_chars below 256 (reduced boundary coverage).",
    )

    @model_validator(mode="after")
    def _validate_overlap(self) -> CacheConfig:
        if self.prefix_overlap_chars <= 0:
            raise ValueError(
                f"prefix_overlap_chars must be positive, got {self.prefix_overlap_chars}"
            )
        below_floor = self.prefix_overlap_chars < _DEFAULT_PREFIX_OVERLAP_CHARS
        if below_floor and not self.allow_unsafe_overlap:
            raise ValueError(
                f"prefix_overlap_chars={self.prefix_overlap_chars} is below the required "
                f"minimum of {_DEFAULT_PREFIX_OVERLAP_CHARS}. Set allow_unsafe_overlap=True "
                f"if you intentionally accept reduced boundary coverage."
            )
        return self
