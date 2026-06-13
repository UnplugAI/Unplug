"""Optional dependency: litellm (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_module

__all__ = ["get_litellm"]


def get_litellm() -> Any:
    return require_module("litellm", pip_extra="litellm", feature="LiteLLM judge")
