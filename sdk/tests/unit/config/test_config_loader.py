"""Tests for core/config_loader.py: TOML loading, env overrides, merging."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from unplug.core.config import GuardConfig
from unplug.core.config_loader import (
    _coerce,
    _merge,
    build_config,
    load,
    load_from_env,
    load_from_file,
)


@pytest.fixture
def toml_file(tmp_path: Path) -> Path:
    p = tmp_path / "unplug.toml"
    p.write_text("""\
[guard]
scanners = ["injection", "destructive"]
mode = "local"
fail_closed = true

[pipeline.thresholds]
block = 0.9
redact = 0.6
review = 0.2

[scanners.injection]
base_score = 0.90
normalize = true
""")
    return p


class TestLoadFromFile:
    def test_loads_toml(self, toml_file: Path):
        data = load_from_file(toml_file)
        assert data["guard"]["scanners"] == ["injection", "destructive"]
        assert data["pipeline"]["thresholds"]["block"] == 0.9

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_from_file("/nonexistent/path.toml")


class TestLoadFromEnv:
    def test_simple_key(self):
        with patch.dict(os.environ, {"UNPLUG_MODE": "server"}):
            result = load_from_env("UNPLUG_")
        assert result["mode"] == "server"

    def test_nested_key(self):
        with patch.dict(os.environ, {"UNPLUG_PIPELINE__THRESHOLDS__BLOCK": "0.95"}):
            result = load_from_env("UNPLUG_")
        assert result["pipeline"]["thresholds"]["block"] == 0.95

    def test_comma_separated_list(self):
        with patch.dict(os.environ, {"UNPLUG_SCANNERS": "injection,destructive"}):
            result = load_from_env("UNPLUG_")
        assert result["scanners"] == ["injection", "destructive"]

    def test_ignores_other_vars(self):
        with patch.dict(os.environ, {"OTHER_VAR": "value"}, clear=False):
            result = load_from_env("UNPLUG_")
        assert "other_var" not in result


class TestCoerce:
    def test_bool_true(self):
        assert _coerce("true") is True
        assert _coerce("yes") is True
        assert _coerce("1") is True

    def test_bool_false(self):
        assert _coerce("false") is False
        assert _coerce("no") is False
        assert _coerce("0") is False

    def test_int(self):
        assert _coerce("42") == 42

    def test_float(self):
        assert _coerce("0.85") == 0.85

    def test_string(self):
        assert _coerce("local") == "local"


class TestMerge:
    def test_flat_merge(self):
        assert _merge({"a": 1}, {"b": 2}) == {"a": 1, "b": 2}

    def test_override(self):
        assert _merge({"a": 1}, {"a": 2}) == {"a": 2}

    def test_deep_merge(self):
        base = {"x": {"a": 1, "b": 2}}
        override = {"x": {"b": 3, "c": 4}}
        assert _merge(base, override) == {"x": {"a": 1, "b": 3, "c": 4}}


class TestBuildConfig:
    def test_from_guard_section(self):
        data = {
            "guard": {"scanners": ["injection"], "mode": "server"},
        }
        cfg = build_config(data)
        assert cfg.scanners == ["injection"]
        assert cfg.mode == "server"

    def test_with_thresholds(self):
        data = {
            "pipeline": {"thresholds": {"block": 0.9, "redact": 0.6}},
        }
        cfg = build_config(data)
        assert cfg.pipeline.thresholds.block == 0.9
        assert cfg.pipeline.thresholds.redact == 0.6

    def test_with_scanner_configs(self):
        data = {
            "scanners": {
                "injection": {"base_score": 0.9, "normalize": True},
            },
        }
        cfg = build_config(data)
        assert "injection" in cfg.scanner_configs
        assert cfg.scanner_configs["injection"].base_score == 0.9


class TestLoad:
    def test_from_file(self, toml_file: Path):
        cfg = load(file_path=toml_file)
        assert cfg.scanners == ["injection", "destructive"]
        assert cfg.pipeline.thresholds.block == 0.9
        assert cfg.pipeline.policy.block_threshold == 0.9

    def test_toolchain_and_collusion_from_example(self) -> None:
        example = Path(__file__).resolve().parents[2] / "unplug.example.toml"
        if not example.exists():
            pytest.skip("unplug.example.toml not found")
        cfg = load(file_path=example)
        assert cfg.toolchain.enabled is True
        assert cfg.toolchain.history_size == 20
        assert cfg.collusion.enabled is True
        assert cfg.collusion.window_seconds == 60.0
        assert cfg.collusion.pair_message_threshold == 10

    def test_fail_closed_false_warns(self) -> None:
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_config({"guard": {"fail_closed": False}})
        assert any(
            issubclass(w.category, DeprecationWarning) and "fail_closed" in str(w.message)
            for w in caught
        )

    def test_judge_enabled_warns(self) -> None:
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_config({"guard": {"judge_enabled": True}})
        assert any(
            issubclass(w.category, DeprecationWarning) and "judge_enabled" in str(w.message)
            for w in caught
        )

    def test_pipeline_judge_timeout_warns(self) -> None:
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            build_config({"pipeline": {"judge_timeout": 60.0}})
        assert any(
            issubclass(w.category, DeprecationWarning) and "judge_timeout" in str(w.message)
            for w in caught
        )

    def test_env_override(self, toml_file: Path):
        with patch.dict(os.environ, {"UNPLUG_GUARD__MODE": "server"}):
            cfg = load(file_path=toml_file)
        assert cfg.mode == "server"

    def test_no_file_defaults(self):
        with patch.dict(
            os.environ,
            {},
            clear=False,
        ):
            os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
            os.environ.pop("UNPLUG_MODEL_PATH", None)
            cfg = load()
        assert cfg == GuardConfig()

    def test_env_only(self):
        with patch.dict(os.environ, {"UNPLUG_GUARD__FAIL_CLOSED": "false"}):
            cfg = load()
        assert cfg.fail_closed is False

    def test_env_model_path_sets_active_model(self, tmp_path: Path) -> None:
        ckpt = tmp_path / "ckpt"
        ckpt.mkdir()
        (ckpt / "config.json").write_text("{}", encoding="utf-8")
        with patch.dict(
            os.environ,
            {"UNPLUG_MODEL_PATH": str(ckpt)},
            clear=False,
        ):
            os.environ.pop("UNPLUG_ACTIVE_MODEL", None)
            cfg = load()
        assert cfg.active_model == "tiny"
        assert cfg.models["tiny"].path == str(ckpt)


class TestGuardConfigFactory:
    def test_from_file(self, toml_file: Path):
        cfg = GuardConfig.from_file(toml_file)
        assert cfg.scanners == ["injection", "destructive"]

    def test_from_dict(self):
        cfg = GuardConfig.from_dict(
            {
                "guard": {"scanners": ["harmful"]},
            }
        )
        assert cfg.scanners == ["harmful"]

    def test_limits_from_toml(self, tmp_path: Path) -> None:
        p = tmp_path / "unplug.toml"
        p.write_text("""\
[limits]
max_input_chars = 100
blocked_tools = ["danger"]
""")
        cfg = load(file_path=p)
        assert cfg.limits.max_input_chars == 100
        assert cfg.limits.blocked_tools == ["danger"]

    def test_messages_from_toml(self, tmp_path: Path) -> None:
        p = tmp_path / "unplug.toml"
        p.write_text("""\
[messages]
blocked_template = "Custom block {category}"
""")
        cfg = load(file_path=p)
        assert "Custom block" in cfg.messages.blocked_template
