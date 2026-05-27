"""Tests for model config in TOML loader."""

from __future__ import annotations

from unplug.config.loader import build_config


def test_build_config_models() -> None:
    cfg = build_config(
        {
            "models": {
                "small": {
                    "name": "unplug-small",
                    "backend": "transformers_span",
                    "path": "/tmp/ckpt",
                    "config": {"inj_threshold": 0.6, "max_length": 512},
                }
            },
            "guard": {"active_model": "small"},
        }
    )
    assert "small" in cfg.models
    assert cfg.models["small"].path == "/tmp/ckpt"
    assert cfg.models["small"].config["inj_threshold"] == 0.6
    assert cfg.active_model == "small"
