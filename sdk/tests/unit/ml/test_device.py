"""Torch device resolution validation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("torch")

from unplug.exceptions import ConfigError
from unplug.ml.device import resolve_torch_device

pytestmark = pytest.mark.requires_ml


def test_forced_cuda_unavailable_raises_config_error() -> None:
    with (
        patch("torch.cuda.is_available", return_value=False),
        pytest.raises(ConfigError, match=r"cuda.*not available"),
    ):
        resolve_torch_device("cuda")


def test_forced_cpu_always_ok() -> None:
    assert resolve_torch_device("cpu") == "cpu"


def test_auto_prefers_cuda_when_available() -> None:
    with (
        patch("torch.cuda.is_available", return_value=True),
        patch("torch.backends.mps.is_available", return_value=True),
    ):
        assert resolve_torch_device(None) == "cuda"
        assert resolve_torch_device("auto") == "cuda"


def test_auto_falls_back_to_mps() -> None:
    mps = MagicMock()
    mps.is_available.return_value = True
    with (
        patch("torch.cuda.is_available", return_value=False),
        patch("torch.backends.mps", mps),
    ):
        assert resolve_torch_device(None) == "mps"


def test_auto_falls_back_to_cpu() -> None:
    mps = MagicMock()
    mps.is_available.return_value = False
    with (
        patch("torch.cuda.is_available", return_value=False),
        patch("torch.backends.mps", mps),
    ):
        assert resolve_torch_device(None) == "cpu"


def test_forced_unknown_device_raises() -> None:
    with pytest.raises(ConfigError, match="not available"):
        resolve_torch_device("tpu")
