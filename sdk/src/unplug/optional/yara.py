"""Optional dependency: yara-python (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_module

__all__ = ["get_yara_module"]


def get_yara_module() -> Any:
    """Return the ``yara`` module; raises with install hint if missing."""
    return require_module("yara", pip_extra="yara", feature="YARA scanner")
