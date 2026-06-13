"""Optional dependency: haystack-ai (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_module

__all__ = ["get_haystack"]


def get_haystack() -> Any:
    return require_module("haystack", pip_extra="haystack", feature="Haystack integration")
