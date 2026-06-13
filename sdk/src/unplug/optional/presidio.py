"""Optional dependency: presidio-analyzer (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_attr

__all__ = ["get_analyzer_engine_class"]


def get_analyzer_engine_class() -> Any:
    """Return Presidio ``AnalyzerEngine`` class; raises with install hint if missing."""
    return require_attr(
        "presidio_analyzer",
        "AnalyzerEngine",
        pip_extra="presidio",
        feature="Presidio PII scanner",
    )
