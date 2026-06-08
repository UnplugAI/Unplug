"""Local model cache — download once from Hugging Face, reuse forever."""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from unplug.core.extras import require_extra
from unplug.core.models import ModelSpec
from unplug.exceptions import ConfigError
from unplug.ml.catalog import CatalogTier, load_catalog


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
        data = json.loads(path.read_text(encoding="utf-8"))
        return ModelManifest.model_validate(data)

    def write_manifest(self, manifest: ModelManifest) -> None:
        tier_dir = self.tier_dir(manifest.tier)
        tier_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path(manifest.tier).write_text(
            manifest.model_dump_json(indent=2),
            encoding="utf-8",
        )

    def resolve_local_path(self, tier: str) -> Path | None:
        """Return cached checkpoint dir if manifest + config.json exist."""
        manifest = self.read_manifest(tier)
        if manifest is None:
            return None
        ckpt = Path(manifest.path)
        if ckpt.is_dir() and (ckpt / "config.json").is_file():
            return ckpt
        return None

    def is_valid_checkpoint(self, path: Path) -> bool:
        return path.is_dir() and (path / "config.json").is_file()

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

        require_extra(
            "huggingface_hub",
            pip_extra="ml",
            feature="Downloading models from Hugging Face Hub",
        )
        from huggingface_hub import snapshot_download

        dest = self.tier_dir(tier) / "checkpoint"
        if force and dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)

        local_dir = snapshot_download(
            repo_id=tier_entry.repo_id,
            revision=tier_entry.revision,
            local_dir=str(dest),
            local_dir_use_symlinks=False,
        )
        ckpt = Path(local_dir)
        if not self.is_valid_checkpoint(ckpt):
            msg = (
                f"Downloaded model at {ckpt} is missing config.json. "
                f"Check repo {tier_entry.repo_id!r} on Hugging Face."
            )
            raise ConfigError(msg)

        self.write_manifest(
            ModelManifest(
                tier=tier,
                repo_id=tier_entry.repo_id,
                revision=tier_entry.revision,
                path=str(ckpt),
            )
        )
        return ckpt

    def list_status(self) -> list[dict[str, Any]]:
        """Status for every catalog tier (installed / upgrade available)."""
        cat = load_catalog()
        rows: list[dict[str, Any]] = []
        for tier_id in cat.tier_names():
            entry = cat.tiers[tier_id]
            manifest = self.read_manifest(tier_id)
            local = self.resolve_local_path(tier_id)
            rows.append(
                {
                    "tier": tier_id,
                    "name": entry.name,
                    "repo_id": entry.repo_id,
                    "catalog_revision": entry.revision,
                    "installed": local is not None,
                    "installed_revision": manifest.revision if manifest else None,
                    "path": str(local) if local else None,
                    "upgrade_available": (
                        manifest is not None
                        and manifest.revision != entry.revision
                        and local is not None
                    ),
                    "description": entry.description,
                }
            )
        return rows

    def resolve_spec_path(self, spec: ModelSpec, tier: str | None = None) -> ModelSpec:
        """Fill spec.path from env override, explicit path, or cache."""
        env_path = os.environ.get("UNPLUG_MODEL_PATH")
        if env_path and self.is_valid_checkpoint(Path(env_path)):
            return spec.model_copy(update={"path": env_path})

        if spec.path and self.is_valid_checkpoint(Path(spec.path)):
            return spec

        cached = self.resolve_local_path(tier or spec.name)
        if cached is not None:
            return spec.model_copy(update={"path": str(cached)})

        return spec
