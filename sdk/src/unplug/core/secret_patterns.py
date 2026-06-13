"""Shared secret-token and PII regex patterns: loaded from packaged YAML."""

from __future__ import annotations

from unplug.core.pattern_loader import (
    leakage_patterns,
    load_privacy_label_map,
    privacy_heuristic_patterns,
    secret_only_patterns,
)

PF_LABEL_MAP: dict[str, str] = load_privacy_label_map()

__all__ = [
    "PF_LABEL_MAP",
    "leakage_patterns",
    "privacy_heuristic_patterns",
    "secret_only_patterns",
]
