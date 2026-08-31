"""Local model cache: download once from Hugging Face, reuse forever."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from unplug.core.runtime.logging import get_logger
from unplug.exceptions import ConfigError
from unplug.ml.catalog import CatalogTier, load_catalog
from unplug.ml.models import ModelSpec
from unplug.optional.ml import require_huggingface_hub

_log = get_logger("ml.store")

_WEIGHT_FILES = ("model.safetensors", "pytorch_model.bin")

# Downloads are safetensors-only by policy (no pickle .bin fetches); .bin
# stays in _WEIGHT_FILES so pre-existing local checkpoints still validate.
_SNAPSHOT_ALLOW_PATTERNS = [
    "*.json",
    "*.safetensors",
    "tokenizer*",
    "spm.model",
    "special_tokens_map.json",
    "added_tokens.json",
    "vocab*",
    "merges.txt",
]


@contextmanager
def _tier_download_lock(tier_dir: Path) -> Iterator[None]:
    """Serialize checkpoint swaps for one tier across threads and processes."""
    tier_dir.mkdir(parents=True, exist_ok=True)
    lock_path = tier_dir / ".download.lock"
    with open(lock_path, "a+", encoding="utf-8") as lock_file:
        try:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        except ImportError:
            pass
        try:
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            except ImportError:
                pass


def _config_digest(path: Path) -> str | None:
    config = path / "config.json"
    if not config.is_file():
        return None
    return hashlib.sha256(config.read_bytes()).hexdigest()[:16]


def default_cache_root() -> Path:
    env = os.environ.get("UNPLUG_MODEL_CACHE")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".cache" / "unplug" / "models"


class ModelManifest(BaseModel):
    """Records what is installed in the local cache for one tier."""

    model_config = {"frozen": True}

    tier: str
    repo_id: str
    revision: str
    path: str
    config_digest: str | None = None
    installed_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


class ModelStore:
    """Download and resolve Unplug checkpoints under a stable cache directory."""

    def __init__(self, cache_root: Path | None = None) -> None:
        self._root = cache_root or default_cache_root()

    @property
    def cache_root(self) -> Path:
        return self._root

    def tier_dir(self, tier: str) -> Path:
        return self._root / tier

    def manifest_path(self, tier: str) -> Path:
        return self.tier_dir(tier) / "manifest.json"

    def read_manifest(self, tier: str) -> ModelManifest | None:
        path = self.manifest_path(tier)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ModelManifest.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as exc:
            _log.warning(
                "Ignoring corrupt manifest for tier %s at %s: %s",
                tier,
                path,
                exc,
            )
            return None

    def write_manifest(self, manifest: ModelManifest) -> None:
        tier_dir = self.tier_dir(manifest.tier)
        tier_dir.mkdir(parents=True, exist_ok=True)
        target = self.manifest_path(manifest.tier)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(
            manifest.model_dump_json(indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, target)

    def is_valid_checkpoint(self, path: Path) -> bool:
        if not path.is_dir() or not (path / "config.json").is_file():
            return False
        if any((path / name).is_file() for name in _WEIGHT_FILES):
            return True
        index_path = path / "model.safetensors.index.json"
        if index_path.is_file():
            try:
                index = json.loads(index_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return False
            weight_map = index.get("weight_map", {})
            if not isinstance(weight_map, dict) or not weight_map:
                return False
            shard_names = set(weight_map.values())
            return all((path / name).is_file() for name in shard_names)
        return any(path.glob("model-*-of-*.safetensors"))

    def _installed_checkpoint(self, tier: str) -> Path | None:
        """Return cached checkpoint when manifest + weights exist (revision may be stale)."""
        manifest = self.read_manifest(tier)
        if manifest is None:
            return None
        ckpt = Path(manifest.path)
        if not self.is_valid_checkpoint(ckpt):
            return None
        digest = _config_digest(ckpt)
        if manifest.config_digest is not None and digest != manifest.config_digest:
            return None
        return ckpt

    def resolve_local_path(self, tier: str) -> Path | None:
        """Return cached checkpoint dir if manifest matches catalog revision."""
        manifest = self.read_manifest(tier)
        if manifest is None:
            return None
        ckpt = Path(manifest.path)
        if not self.is_valid_checkpoint(ckpt):
            return None

        cat = load_catalog()
        entry = cat.get(tier)
        if entry is not None and manifest.revision != entry.revision:
            return None

        digest = _config_digest(ckpt)
        if manifest.config_digest is not None and digest != manifest.config_digest:
            return None

        return ckpt

    def ensure_tier(
        self,
        tier: str,
        *,
        force: bool = False,
        entry: CatalogTier | None = None,
    ) -> Path:
        """Download tier from Hugging Face if missing; return local checkpoint path."""
        existing = self.resolve_local_path(tier)
        if existing is not None and not force:
            return existing

        cat = load_catalog()
        tier_entry = entry or cat.get(tier)
        if tier_entry is None:
            msg = f"Unknown model tier {tier!r}. Available: {', '.join(cat.tier_names())}"
            raise ConfigError(msg)

        require_huggingface_hub()
        from huggingface_hub import snapshot_download

        dest = self.tier_dir(tier) / "checkpoint"
        staging_id = f"{os.getpid()}-{threading.get_ident()}"
        temp_dest = self.tier_dir(tier) / f".checkpoint-download-{staging_id}"
        backup = self.tier_dir(tier) / f".checkpoint-{staging_id}.bak"

        with _tier_download_lock(self.tier_dir(tier)):
            if temp_dest.exists():
                shutil.rmtree(temp_dest)
            temp_dest.mkdir(parents=True, exist_ok=True)

            moved_to_backup = False
            manifest_written = False
            previous_manifest = self.read_manifest(tier)
            try:
                local_dir = snapshot_download(
                    repo_id=tier_entry.repo_id,
                    revision=tier_entry.revision,
                    local_dir=str(temp_dest),
                    allow_patterns=_SNAPSHOT_ALLOW_PATTERNS,
                )
                ckpt = Path(local_dir)
                if not self.is_valid_checkpoint(ckpt):
                    msg = (
                        f"Downloaded model at {ckpt} is missing config.json or weight files. "
                        f"Check repo {tier_entry.repo_id!r} on Hugging Face."
                    )
                    raise ConfigError(msg)

                manifest = ModelManifest(
                    tier=tier,
                    repo_id=tier_entry.repo_id,
                    revision=tier_entry.revision,
                    path=str(dest),
                    config_digest=_config_digest(ckpt),
                )

                if backup.exists():
                    shutil.rmtree(backup)
                if dest.exists():
                    os.replace(dest, backup)
                    moved_to_backup = True
                os.replace(ckpt, dest)
                self.write_manifest(manifest)
                manifest_written = True
                if backup.exists():
                    shutil.rmtree(backup)
                return dest
            except Exception:
                # Roll back to the last good checkpoint so a failed swap never
                # strands the tier without a model (manifest still matches it).
                if moved_to_backup and backup.exists():
                    if dest.exists():
                        shutil.rmtree(dest)
                    os.replace(backup, dest)
                if manifest_written:
                    if previous_manifest is not None:
                        self.write_manifest(previous_manifest)
                    elif self.manifest_path(tier).is_file():
                        self.manifest_path(tier).unlink()
                if temp_dest.exists():
                    shutil.rmtree(temp_dest)
                raise

    def list_status(self) -> list[dict[str, Any]]:
        """Status for every catalog tier (installed / upgrade available)."""
        cat = load_catalog()
        rows: list[dict[str, Any]] = []
        for tier_id in cat.tier_names():
            entry = cat.tiers[tier_id]
            manifest = self.read_manifest(tier_id)
            installed_ckpt = self._installed_checkpoint(tier_id)
            rows.append(
                {
                    "tier": tier_id,
                    "name": entry.name,
                    "repo_id": entry.repo_id,
                    "catalog_revision": entry.revision,
                    "installed": installed_ckpt is not None,
                    "installed_revision": manifest.revision if manifest else None,
                    "path": str(installed_ckpt) if installed_ckpt else None,
                    "upgrade_available": (
                        manifest is not None
                        and manifest.revision != entry.revision
                        and installed_ckpt is not None
                    ),
                    "description": entry.description,
                }
            )
        return rows

    def resolve_spec_path(self, spec: ModelSpec, tier: str | None = None) -> ModelSpec:
        """Fill spec.path from env override, explicit path, or cache.

        The cache is only consulted when no checkpoint was asked for by name.
        An operator who pins a path or sets ``UNPLUG_MODEL_PATH`` has named the
        weights they want scanning their traffic, so a bad value there must not
        be quietly answered with a different model out of the cache (#149).
        Leaving the unusable path in place lets the caller decide what to do:
        download it when ``auto_download_model`` is set, or fail.
        """
        env_path = os.environ.get("UNPLUG_MODEL_PATH")
        if env_path:
            env = Path(env_path)
            if self.is_valid_checkpoint(env):
                return spec.model_copy(update={"path": env_path})
            _log.warning(
                "UNPLUG_MODEL_PATH=%s is set but is not a valid checkpoint "
                "(need config.json and model.safetensors or pytorch_model.bin). "
                "Not falling back to the model cache: unset it to use the cache.",
                env_path,
            )
            # The bad path is written onto the spec, not dropped. Returning the spec
            # unchanged leaves path unset, which downstream reads as "nothing was
            # asked for" and answers from the cache or a download: the substitution
            # this warning promises is not happening.
            return spec.model_copy(update={"path": env_path})

        if spec.path:
            if self.is_valid_checkpoint(Path(spec.path)):
                return spec
            _log.warning(
                "Configured model path %s is not a valid checkpoint. "
                "Not falling back to the model cache.",
                spec.path,
            )
            return spec

        cached = self.resolve_local_path(tier or spec.name)
        if cached is not None:
            return spec.model_copy(update={"path": str(cached)})

        return spec
