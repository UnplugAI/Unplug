"""Torch device selection for optional ML extras."""

from __future__ import annotations


def resolve_torch_device(preferred: str | None = None) -> str:
    if preferred and preferred not in ("auto", ""):
        return preferred
    import torch

    if torch.cuda.is_available():
        return "cuda"
    if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
        return "mps"
    return "cpu"
