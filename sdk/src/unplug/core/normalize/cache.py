"""Shared normalization cache for pipeline-level reuse."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unplug.core.normalize.normalize import Normalizer, NormalizeResult

if TYPE_CHECKING:
    from unplug.core.context import ExecutionContext


def cached_normalize(
    context: ExecutionContext,
    normalizer: Normalizer,
    text: str,
    *,
    cache_key: str = "full",
) -> NormalizeResult:
    """Normalize once per cache key and source text per scan context."""
    cached = context.get_norm_result(cache_key)
    if cached is not None and cached.original == text:
        return cached
    result = normalizer.normalize(text)
    context.normalize_cache[cache_key] = result
    return result
