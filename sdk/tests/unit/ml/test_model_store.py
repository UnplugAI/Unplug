"""Tests for model catalog and local cache store."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from types import ModuleType

import pytest

from unplug.config.guard import GuardConfig
from unplug.core.runtime.model_runtime import merge_catalog_models, resolve_active_model_spec
from unplug.exceptions import ConfigError, ModelError
from unplug.ml.catalog import load_catalog
from unplug.ml.store import ModelManifest, ModelStore, _config_digest


def _write_checkpoint(
    ckpt: Path,
    *,
    config: str = "{}",
    weights: bytes = b"x" * 10,
) -> None:
    ckpt.mkdir(parents=True, exist_ok=True)
    (ckpt / "config.json").write_text(config, encoding="utf-8")
    (ckpt / "model.safetensors").write_bytes(weights)


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
    _write_checkpoint(ckpt)
    manifest = store.read_manifest("tiny")
    assert manifest is None
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
    _write_checkpoint(ckpt)
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
    _write_checkpoint(ckpt, config='{"model": "test"}')
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
    _write_checkpoint(ckpt)
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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
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


def test_corrupt_manifest_returns_none_and_list_status_ok(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    store = ModelStore(cache_root=tmp_path)
    manifest_path = store.manifest_path("tiny")
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{truncated", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="unplug.ml.store"):
        assert store.read_manifest("tiny") is None
        assert store.resolve_local_path("tiny") is None
        rows = store.list_status()
    assert rows[0]["tier"] == "tiny"
    assert rows[0]["installed"] is False
    assert "corrupt manifest" in caplog.text.lower()


def test_unknown_active_model_raises_config_error() -> None:
    cfg = merge_catalog_models(GuardConfig(active_model="typo"))
    with pytest.raises(ConfigError, match="Valid tiers"):
        resolve_active_model_spec(cfg)


def test_ensure_tier_redownloads_when_weights_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    ckpt.mkdir(parents=True)
    (ckpt / "config.json").write_text("{}", encoding="utf-8")
    store.write_manifest(
        ModelManifest(
            tier="tiny",
            repo_id="Unplug-AI/test",
            revision=load_catalog().tiers["tiny"].revision,
            path=str(ckpt),
        )
    )
    assert store.resolve_local_path("tiny") is None

    def fake_snapshot_download(**kwargs: object) -> str:
        local_dir = Path(str(kwargs["local_dir"]))
        _write_checkpoint(local_dir)
        return str(local_dir)

    hf = ModuleType("huggingface_hub")
    hf.snapshot_download = fake_snapshot_download  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "huggingface_hub", hf)
    monkeypatch.setattr(
        "unplug.ml.store.require_huggingface_hub",
        lambda: None,
    )

    resolved = store.ensure_tier("tiny")
    assert resolved == ckpt
    assert store.is_valid_checkpoint(resolved)


def test_is_valid_checkpoint_accepts_sharded_safetensors(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "sharded"
    ckpt.mkdir()
    (ckpt / "config.json").write_text("{}", encoding="utf-8")
    (ckpt / "model.safetensors.index.json").write_text("{}", encoding="utf-8")
    (ckpt / "model-00001-of-00002.safetensors").write_bytes(b"x" * 10)
    assert store.is_valid_checkpoint(ckpt)


def test_stale_revision_reports_installed_and_upgrade_available(tmp_path: Path) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    _write_checkpoint(ckpt)
    store.write_manifest(
        ModelManifest(
            tier="tiny",
            repo_id="Unplug-AI/test",
            revision="stale-revision",
            path=str(ckpt),
        )
    )
    row = next(r for r in store.list_status() if r["tier"] == "tiny")
    assert row["installed"] is True
    assert row["upgrade_available"] is True
    assert store.resolve_local_path("tiny") is None


def test_force_download_failure_preserves_old_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    _write_checkpoint(ckpt, config='{"model": "keep"}')
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

    def boom(**kwargs: object) -> str:
        msg = "network down"
        raise RuntimeError(msg)

    hf = ModuleType("huggingface_hub")
    hf.snapshot_download = boom  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "huggingface_hub", hf)
    monkeypatch.setattr(
        "unplug.ml.store.require_huggingface_hub",
        lambda: None,
    )

    with pytest.raises(RuntimeError, match="network down"):
        store.ensure_tier("tiny", force=True)

    assert store.resolve_local_path("tiny") == ckpt


def test_failed_swap_restores_backup_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure after the old checkpoint moved to backup must roll it back."""
    store = ModelStore(cache_root=tmp_path)
    ckpt = tmp_path / "tiny" / "checkpoint"
    _write_checkpoint(ckpt, config='{"model": "keep"}')
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

    def fake_snapshot_download(**kwargs: object) -> str:
        local_dir = Path(str(kwargs["local_dir"]))
        _write_checkpoint(local_dir, config='{"model": "new"}')
        return str(local_dir)

    hf = ModuleType("huggingface_hub")
    hf.snapshot_download = fake_snapshot_download  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "huggingface_hub", hf)
    monkeypatch.setattr(
        "unplug.ml.store.require_huggingface_hub",
        lambda: None,
    )

    def broken_write(manifest: ModelManifest) -> None:
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(store, "write_manifest", broken_write)

    with pytest.raises(OSError, match="disk full"):
        store.ensure_tier("tiny", force=True)

    # Old checkpoint restored at the original path; manifest still matches it.
    assert (ckpt / "config.json").read_text(encoding="utf-8") == '{"model": "keep"}'
    assert store.resolve_local_path("tiny") == ckpt
    leftovers = [
        p.name
        for p in (tmp_path / "tiny").iterdir()
        if p.name not in {"checkpoint", ".download.lock"}
    ]
    assert leftovers == ["manifest.json"]


def test_invalid_unplug_model_path_logs_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    bad = tmp_path / "bad_ckpt"
    bad.mkdir()
    (bad / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("UNPLUG_MODEL_PATH", str(bad))
    store = ModelStore(cache_root=tmp_path / "cache")
    spec = load_catalog().tiers["tiny"].to_model_spec()
    with caplog.at_level(logging.WARNING, logger="unplug.ml.store"):
        resolved = store.resolve_spec_path(spec, tier="tiny")
    assert resolved.path is None
    assert "UNPLUG_MODEL_PATH" in caplog.text
    assert str(bad) in caplog.text
