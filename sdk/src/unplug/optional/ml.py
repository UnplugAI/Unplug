"""Optional dependency: ML stack (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_module

__all__ = ["get_torch", "get_transformers", "require_huggingface_hub"]


def get_torch() -> Any:
    return require_module("torch", pip_extra="ml", feature="ML span model")


def get_transformers() -> Any:
    return require_module("transformers", pip_extra="ml", feature="ML span model")


def require_huggingface_hub() -> Any:
    return require_module("huggingface_hub", pip_extra="ml", feature="Model download")
