"""Load bundled model tier catalog from data/catalog.toml."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from unplug.ml.models import ModelSpec

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "catalog.toml"


class CatalogTier(BaseModel):
    """One downloadable model tier from catalog.toml."""

    model_config = {"frozen": True}

    tier: str
    name: str
    repo_id: str
    revision: str = "main"
    backend: str = "transformers_span"
    description: str = ""
    config: dict[str, Any] = Field(default_factory=dict)

    def to_model_spec(self, *, path: str | None = None) -> ModelSpec:
        return ModelSpec(
            name=self.name,
            version=self.revision,
            backend=self.backend,
            path=path,
            repo_id=self.repo_id,
            config=dict(self.config),
        )


class ModelCatalog(BaseModel):
    """Parsed catalog with tier lookup."""

    model_config = {"frozen": True}

    default_tier: str = "tiny"
    tiers: dict[str, CatalogTier] = Field(default_factory=dict)

    def get(self, tier: str) -> CatalogTier | None:
        return self.tiers.get(tier)

    def tier_names(self) -> list[str]:
        return sorted(self.tiers.keys())


@lru_cache(maxsize=1)
def load_catalog(path: Path | None = None) -> ModelCatalog:
    """Load catalog.toml (cached)."""
    p = path or _CATALOG_PATH
    if not p.is_file():
        msg = f"Model catalog not found: {p}"
        raise FileNotFoundError(msg)
    with p.open("rb") as f:
        raw = tomllib.load(f)
    meta = raw.get("catalog", raw)
    default_tier = str(meta.get("default_tier", "tiny"))
    tiers_raw = meta.get("tiers", {})
    tiers: dict[str, CatalogTier] = {}
    for tier_id, entry in tiers_raw.items():
        if not isinstance(entry, dict):
            continue
        cfg = entry.get("config", {})
        tiers[tier_id] = CatalogTier(
            tier=tier_id,
            name=str(entry.get("name", tier_id)),
            repo_id=str(entry["repo_id"]),
            revision=str(entry.get("revision", "main")),
            backend=str(entry.get("backend", "transformers_span")),
            description=str(entry.get("description", "")),
            config=dict(cfg) if isinstance(cfg, dict) else {},
        )
    return ModelCatalog(default_tier=default_tier, tiers=tiers)


def catalog_model_spec(tier: str, *, path: str | None = None) -> ModelSpec | None:
    cat = load_catalog()
    entry = cat.get(tier)
    if entry is None:
        return None
    return entry.to_model_spec(path=path)
