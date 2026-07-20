"""Torch device selection for optional ML extras."""

from __future__ import annotations

from unplug.exceptions import ConfigError


def resolve_torch_device(preferred: str | None = None) -> str:
    """Resolve a torch device string, validating forced preferences.

    Raises:
        ConfigError: when ``preferred`` names a device torch cannot use.
    """
    from unplug.optional.ml import get_torch

    torch = get_torch()
    available: list[str] = ["cpu"]
    if torch.cuda.is_available():
        available.append("cuda")
    mps_backend = getattr(torch.backends, "mps", None)
    if mps_backend is not None and mps_backend.is_available():
        available.append("mps")

    if preferred and preferred not in ("auto", ""):
        device = preferred.strip()
        if not _device_available(device, torch=torch, mps_backend=mps_backend):
            msg = f"Torch device '{device}' is not available. Available: {', '.join(available)}"
            raise ConfigError(msg)
        return device

    if "cuda" in available:
        return "cuda"
    if "mps" in available:
        return "mps"
    return "cpu"


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
