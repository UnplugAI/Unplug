"""Runtime utilities: cache, stats, logging, asyncio, model runtime, versions."""

from __future__ import annotations

from unplug.core.runtime.asyncio_compat import run_coroutine_sync
from unplug.core.runtime.cache import SafePrefixState, ScanCache, merge_suffix_result
from unplug.core.runtime.logging import correlation_scope, get_correlation_id, get_logger
from unplug.core.runtime.model_runtime import load_active_model_provider, prepare_active_model_spec
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION

__all__ = [
    "MODEL_VERSION_LOCAL",
    "NORMALIZER_VERSION",
    "MetricsCollector",
    "SafePrefixState",
    "ScanCache",
    "correlation_scope",
    "get_correlation_id",
    "get_logger",
    "load_active_model_provider",
    "merge_suffix_result",
    "prepare_active_model_spec",
    "run_coroutine_sync",
]
