"""Torch device selection for optional ML extras."""

from __future__ import annotations

from typing import Any

from unplug.exceptions import ConfigError


def resolve_torch_device(preferred: str | None = None) -> str:
    """Resolve a torch device string, validating forced preferences.

    Forcing "cpu" never imports torch, so constructing a model on the CPU
    stays lazy for environments without the ML extras installed.

    Raises:
        ConfigError: when ``preferred`` names a device torch cannot use.
    """
    device = (preferred or "").strip()
    if device and device != "auto":
        if device == "cpu":
            return device
        return _validate_forced_device(device)

    from unplug.optional.ml import get_torch

    torch = get_torch()
    if torch.cuda.is_available():
        return "cuda"
    mps_backend = getattr(torch.backends, "mps", None)
    if mps_backend is not None and mps_backend.is_available():
        return "mps"
    return "cpu"


def _validate_forced_device(device: str) -> str:
    from unplug.optional.ml import get_torch

    torch = get_torch()
    try:
        parsed = torch.device(device)
    except (RuntimeError, ValueError) as exc:
        msg = f"Torch device '{device}' is not valid. Available: {_available_devices(torch)}"
        raise ConfigError(msg) from exc

    if not _backend_available(torch, parsed.type):
        msg = f"Torch device '{device}' is not available. Available: {_available_devices(torch)}"
        raise ConfigError(msg)
    return device


def _backend_available(torch: Any, backend: str) -> bool:
    if backend == "cpu":
        return True
    if backend == "cuda":
        return bool(torch.cuda.is_available())
    if backend == "mps":
        mps_backend = getattr(torch.backends, "mps", None)
        return mps_backend is not None and bool(mps_backend.is_available())
    # Other accelerators (xpu, hpu, ...): probe torch.<backend>.is_available()
    # when the module exposes one, otherwise trust torch's device parsing.
    module = getattr(torch, backend, None)
    is_available = getattr(module, "is_available", None)
    if callable(is_available):
        return bool(is_available())
    return True


def _available_devices(torch: Any) -> str:
    available = ["cpu"]
    if torch.cuda.is_available():
        available.append("cuda")
    mps_backend = getattr(torch.backends, "mps", None)
    if mps_backend is not None and mps_backend.is_available():
        available.append("mps")
    return ", ".join(available)
