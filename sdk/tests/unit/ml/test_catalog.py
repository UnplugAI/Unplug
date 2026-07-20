"""Offline invariants for the bundled model catalog."""

from __future__ import annotations

import re

from unplug.ml.catalog import load_catalog

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO_PREFIX = "Unplug-AI/"


def test_catalog_revisions_are_full_commit_shas() -> None:
    cat = load_catalog()
    assert cat.tiers, "catalog must define at least one tier"
    for tier_id, entry in cat.tiers.items():
        assert _FULL_SHA.match(entry.revision), (
            f"tier {tier_id!r}: revision must be a 40-char hex SHA, got {entry.revision!r}"
        )


def test_catalog_repo_ids_use_official_org() -> None:
    cat = load_catalog()
    for tier_id, entry in cat.tiers.items():
        assert entry.repo_id.startswith(_REPO_PREFIX), (
            f"tier {tier_id!r}: repo_id must start with {_REPO_PREFIX!r}, got {entry.repo_id!r}"
        )
