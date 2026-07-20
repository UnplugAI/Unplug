"""CLI tests for unplug-models without network or model downloads."""

from __future__ import annotations

import argparse
import json
import sys
from types import SimpleNamespace

import pytest

from unplug.cli import models
from unplug.exceptions import ConfigError, ModelError


class _FakeStore:
    cache_root = "/tmp/unplug-models"

    def __init__(self) -> None:
        self.force_seen: bool | None = None

    def list_status(self) -> list[dict]:
        return [
            {
                "tier": "tiny",
                "name": "Tiny",
                "installed": False,
                "repo_id": "Unplug-AI/tiny",
                "catalog_revision": "abc123",
                "description": "small model",
            },
            {
                "tier": "medium",
                "name": "Medium",
                "installed": True,
                "upgrade_available": True,
                "repo_id": "Unplug-AI/medium",
                "catalog_revision": "def456",
                "path": "/models/medium",
            },
        ]

    def ensure_tier(self, tier: str, *, force: bool = False) -> str:
        self.force_seen = force
        if tier == "bad-config":
            raise ConfigError("bad config")
        if tier == "bad-model":
            raise ModelError("bad model")
        if tier == "boom":
            raise RuntimeError("network")
        return f"/models/{tier}"


def _catalog() -> SimpleNamespace:
    return SimpleNamespace(default_tier="tiny")


def test_models_list_text(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(models, "ModelStore", _FakeStore)
    monkeypatch.setattr(models, "load_catalog", _catalog)

    code = models._cmd_list(argparse.Namespace(format="text"))

    assert code == 0
    out = capsys.readouterr().out
    assert "Default tier: tiny" in out
    assert "upgrade available" in out
    assert "small model" in out


def test_models_list_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(models, "ModelStore", _FakeStore)

    code = models._cmd_list(argparse.Namespace(format="json"))

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["tier"] == "tiny"


def test_models_download_success_and_default_tier(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(models, "ModelStore", _FakeStore)
    monkeypatch.setattr(models, "load_catalog", _catalog)

    code = models._cmd_download(argparse.Namespace(tier=None, force=False))

    assert code == 0
    assert "Downloaded tiny" in capsys.readouterr().out


@pytest.mark.parametrize("tier", ["bad-config", "bad-model"])
def test_models_download_known_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tier: str,
) -> None:
    monkeypatch.setattr(models, "ModelStore", _FakeStore)

    code = models._cmd_download(argparse.Namespace(tier=tier, force=False))

    assert code == 1
    assert "Error:" in capsys.readouterr().err


def test_models_download_unexpected_error_mentions_ml_extra(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(models, "ModelStore", _FakeStore)

    code = models._cmd_download(argparse.Namespace(tier="boom", force=False))

    assert code == 1
    assert "pip install 'unplug-ai[ml]'" in capsys.readouterr().err


def test_models_status(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(models, "active_model_status", lambda: {"active": False})

    code = models._cmd_status(argparse.Namespace())

    assert code == 0
    assert json.loads(capsys.readouterr().out) == {"active": False}


def test_models_main_dispatches_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_download(args: argparse.Namespace) -> int:
        seen["tier"] = args.tier
        seen["force"] = args.force
        return 0

    monkeypatch.setattr(models, "_cmd_download", fake_download)
    monkeypatch.setattr(sys, "argv", ["unplug-models", "upgrade", "tiny"])

    with pytest.raises(SystemExit) as exc:
        models.main()

    assert exc.value.code == 0
    assert seen == {"tier": "tiny", "force": True}
