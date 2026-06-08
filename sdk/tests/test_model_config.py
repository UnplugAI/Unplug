"""Tests for model config in TOML loader."""

from __future__ import annotations

from unplug.config.loader import build_config


def test_build_config_models() -> None:
    cfg = build_config(
        {
            "models": {
                "tiny": {
                    "name": "unplug-tiny",
                    "backend": "transformers_span",
                    "path": "/tmp/ckpt",
                    "config": {"inj_threshold": 0.6, "max_length": 512},
                }
            },
            "guard": {"active_model": "tiny"},
        }
    )
    assert "tiny" in cfg.models
    assert cfg.models["tiny"].path == "/tmp/ckpt"
    assert cfg.models["tiny"].config["inj_threshold"] == 0.6
    assert cfg.active_model == "tiny"
