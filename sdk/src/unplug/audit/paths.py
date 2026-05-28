"""Resolve bundled audit probe files (CI-safe) with monorepo fallback."""

from __future__ import annotations

from pathlib import Path

_PKG_DATA = Path(__file__).resolve().parent / "data"

_MONOREPO_REL: dict[str, str] = {
    "fp_probe_queries.json": "repos/unplug_exp/configs/fp_probe_queries.json",
    "encoding_probe_queries.json": "repos/unplug_exp/configs/encoding_probe_queries.json",
    "agent_boundary_probe_queries.json": (
        "repos/unplug_exp/configs/agent_boundary_probe_queries.json"
    ),
}


def resolve_probe_path(filename: str, workspace_root: Path) -> Path:
    """Prefer bundled SDK data; fall back to unplug_exp in local monorepo."""
    bundled = _PKG_DATA / filename
    if bundled.is_file():
        return bundled
    rel = _MONOREPO_REL.get(filename)
    if rel is not None:
        monorepo = workspace_root / rel
        if monorepo.is_file():
            return monorepo
    return bundled
