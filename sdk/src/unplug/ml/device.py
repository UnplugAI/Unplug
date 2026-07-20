"""Torch device selection for optional ML extras."""

from __future__ import annotations

from unplug.exceptions import ConfigError


def resolve_torch_device(preferred: str | None = None) -> str:
    """Resolve a torch device string, validating forced preferences.

    Forcing "cpu" never imports torch, so constructing a model on the CPU
    stays lazy for environments without the ML extras installed.

    Raises:
        ConfigError: when ``preferred`` names a device torch cannot use.
    """
    if preferred and preferred not in ("auto", ""):
        device = preferred.strip()
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
    mps_backend = getattr(torch.backends, "mps", None)
    if _device_available(device, torch=torch, mps_backend=mps_backend):
        return device

    available = ["cpu"]
    if torch.cuda.is_available():
        available.append("cuda")
    if mps_backend is not None and mps_backend.is_available():
        available.append("mps")
    msg = f"Torch device '{device}' is not available. Available: {', '.join(available)}"
    raise ConfigError(msg)


def _device_available(
    device: str,
    *,
    torch: object,
    mps_backend: object | None,
) -> bool:
    if device == "cpu":
        return True
    if device == "cuda" or device.startswith("cuda:"):
        return bool(torch.cuda.is_available())  # type: ignore[attr-defined]
    if device == "mps":
        return mps_backend is not None and bool(mps_backend.is_available())  # type: ignore[attr-defined]
    return False
