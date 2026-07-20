"""Tests for model catalog and local cache store."""

from __future__ import annotations

from pathlib import Path

import pytest

from unplug.config.guard import GuardConfig
from unplug.core.runtime.model_runtime import merge_catalog_models
from unplug.exceptions import ModelError
from unplug.ml.catalog import load_catalog
from unplug.ml.store import ModelStore


def test_catalog_loads_tiny_tier() -> None:
    cat = load_catalog()
    assert cat.default_tier == "tiny"
    assert "tiny" in cat.tiers
    assert cat.tiers["tiny"].repo_id == "Unplug-AI/unplug-tiny-v1"


def test_merge_catalog_injects_tiers() -> None:
    cfg = merge_catalog_models(GuardConfig())
    assert "tiny" in cfg.models
    assert cfg.models["tiny"].name == "unplug-tiny"


def test_store_manifest_roundtrip(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    ckpt.mkdir(parents=True)
    (ckpt / "config.json").write_text("{}", encoding="utf-8")
    manifest = store.read_manifest("tiny")
    assert manifest is None
    from unplug.ml.store import ModelManifest

    store.write_manifest(
        ModelManifest(
            tier="tiny",
            repo_id="Unplug-AI/test",
            revision=load_catalog().tiers["tiny"].revision,
            path=str(ckpt),
            config_digest="abc123",
        )
    )
    resolved = store.resolve_local_path("tiny")
    assert resolved is None


def test_store_rejects_stale_catalog_revision(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    ckpt.mkdir(parents=True)
    (ckpt / "config.json").write_text("{}", encoding="utf-8")
    from unplug.ml.store import ModelManifest

    store.write_manifest(
        ModelManifest(
            tier="tiny",
            repo_id="Unplug-AI/test",
            revision="stale-revision",
            path=str(ckpt),
        )
    )
    assert store.resolve_local_path("tiny") is None


def test_store_accepts_matching_revision_and_digest(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    ckpt.mkdir(parents=True)
    (ckpt / "config.json").write_text('{"model": "test"}', encoding="utf-8")
    from unplug.ml.store import ModelManifest, _config_digest

    digest = _config_digest(ckpt)
    store.write_manifest(
        ModelManifest(
            tier="tiny",
            repo_id="Unplug-AI/test",
            revision=load_catalog().tiers["tiny"].revision,
            path=str(ckpt),
            config_digest=digest,
        )
    )
    assert store.resolve_local_path("tiny") == ckpt


def test_env_path_overrides_cache(tmp_path: Path, monkeypatch) -> None:
    ckpt = tmp_path / "env_ckpt"
    ckpt.mkdir()
    (ckpt / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("UNPLUG_MODEL_PATH", str(ckpt))
    store = ModelStore(cache_root=tmp_path / "cache")
    spec = load_catalog().tiers["tiny"].to_model_spec()
    resolved = store.resolve_spec_path(spec, tier="tiny")
    assert resolved.path == str(ckpt)


def test_require_ml_raises_when_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    monkeypatch.setenv("UNPLUG_MODEL_CACHE", str(tmp_path / "empty_cache"))
    cfg = GuardConfig(active_model="tiny", require_ml=True, auto_download_model=False)
    cfg = merge_catalog_models(cfg)
    try:
        from unplug import Guard

        Guard(config=cfg)
    except ModelError as exc:
        assert "download" in str(exc).lower() or "require_ml" in str(exc).lower()
    else:
        raise AssertionError("expected ModelError")


def test_list_status_includes_all_tiers(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    rows = store.list_status()
    tiers = {r["tier"] for r in rows}
    assert tiers == set(load_catalog().tier_names())


def test_guard_survives_corrupt_checkpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """active_model with invalid checkpoint must not crash Guard when require_ml=false."""
    pytest.importorskip("torch")
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    ckpt = tmp_path / "corrupt"
    ckpt.mkdir()
    (ckpt / "config.json").write_text("not-json", encoding="utf-8")
    cfg = merge_catalog_models(
        GuardConfig(active_model="tiny", require_ml=False, auto_download_model=False)
    )
    models = dict(cfg.models)
    models["tiny"] = models["tiny"].model_copy(update={"path": str(ckpt)})
    cfg = cfg.model_copy(update={"models": models})

    from unplug import Guard

    guard = Guard(config=cfg)
    assert guard.ml_model_loaded is False
    assert "injection_ml" not in guard.scanners_loaded


def test_guard_require_ml_corrupt_checkpoint_raises_model_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("torch")
    monkeypatch.delenv("UNPLUG_MODEL_PATH", raising=False)
    ckpt = tmp_path / "corrupt"
    ckpt.mkdir()
    (ckpt / "config.json").write_text("not-json", encoding="utf-8")
    cfg = merge_catalog_models(
        GuardConfig(active_model="tiny", require_ml=True, auto_download_model=False)
    )
    models = dict(cfg.models)
    models["tiny"] = models["tiny"].model_copy(update={"path": str(ckpt)})
    cfg = cfg.model_copy(update={"models": models})

    from unplug import Guard

    with pytest.raises(ModelError, match="require_ml"):
        Guard(config=cfg)
