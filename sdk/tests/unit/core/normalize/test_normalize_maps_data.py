"""Tests for packaged normalizer TOML maps."""

from __future__ import annotations

from unplug.core.normalize.normalize import (
    _HOMOGLYPH_MAP,
    _LEET_MAP,
    _OVERRIDE_VERBS,
    _ZERO_WIDTH_CHARS,
    _normalize_homoglyphs,
    _normalize_leet,
)
from unplug.data.maps_loader import load_normalize_maps


def test_normalize_toml_loads() -> None:
    maps = load_normalize_maps()
    assert maps.leet["3"] == "e"
    assert maps.homoglyphs["а"] == "a"
    assert maps.override_verbs["ignorar"] == "ignore"
    assert "\u200b" in maps.zero_width_chars
    assert "\u202e" in maps.zero_width_chars  # RTL override (token smuggling)
    assert "\u2066" in maps.zero_width_chars  # LRI


def test_module_maps_match_bundled_data() -> None:
    maps = load_normalize_maps()
    assert maps.leet == _LEET_MAP
    assert maps.homoglyphs == _HOMOGLYPH_MAP
    assert maps.override_verbs == _OVERRIDE_VERBS
    assert set(maps.zero_width_chars) == _ZERO_WIDTH_CHARS


def test_leet_and_homoglyph_stages_unchanged() -> None:
    offsets = list(range(6))
    leet_text, _ = _normalize_leet("1gn0r3", offsets)
    assert leet_text == "ignore"
    homo_text, _ = _normalize_homoglyphs("аttack", offsets)
    assert homo_text == "attack"
