"""Load tool/agent TOML maps from unplug.data.maps (avoids core import cycles)."""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib import resources
from typing import TYPE_CHECKING

from unplug.data.schemas import (
    AgentToolsMap,
    NormalizeMaps,
    ScannerDefaultEntry,
    SuspiciousChainEntry,
    ToolchainMaps,
    ToolPatternsMap,
    ToolProfileMapEntry,
)

if TYPE_CHECKING:
    from unplug.config.guard import ScannerConfig


def _read_text(resource: str) -> str:
    return resources.files("unplug.data.maps").joinpath(resource).read_text(encoding="utf-8")


def _tuple_str_list(section: dict[str, object], key: str) -> tuple[str, ...]:
    values = section.get(key, [])
    if not isinstance(values, list):
        msg = f"{key}: expected list"
        raise TypeError(msg)
    return tuple(str(value) for value in values)


def _parse_tool_profile_entry(section: dict[str, object]) -> ToolProfileMapEntry:
    blocked = _tuple_str_list(section, "blocked_patterns")
    allowed_raw = section.get("allowed_patterns")
    allowed: tuple[str, ...] | None
    if allowed_raw is None:
        allowed = None
    elif isinstance(allowed_raw, list):
        allowed = tuple(str(value) for value in allowed_raw)
    else:
        msg = "allowed_patterns must be a list or omitted"
        raise TypeError(msg)
    return ToolProfileMapEntry(blocked_patterns=blocked, allowed_patterns=allowed)


def _parse_toolchain_maps(section: dict[str, object]) -> ToolchainMaps:
    def _tool_set(key: str) -> frozenset[str]:
        nested = section.get(key, {})
        if not isinstance(nested, dict):
            msg = f"toolchain.{key} must be a table"
            raise TypeError(msg)
        return frozenset(str(name) for name in _tuple_str_list(nested, "tools"))

    chains_raw = section.get("suspicious_chains", [])
    if not isinstance(chains_raw, list):
        msg = "toolchain.suspicious_chains must be a list"
        raise TypeError(msg)
    chains = tuple(SuspiciousChainEntry.model_validate(item) for item in chains_raw)
    regex = section.get("sensitive_path_regex")
    if not isinstance(regex, str) or not regex.strip():
        msg = "toolchain.sensitive_path_regex must be a non-empty string"
        raise TypeError(msg)
    return ToolchainMaps(
        read_tools=_tool_set("read_tools"),
        write_tools=_tool_set("write_tools"),
        network_tools=_tool_set("network_tools"),
        exec_tools=_tool_set("exec_tools"),
        sensitive_path_regex=regex,
        chain_score=float(section.get("chain_score", 0.88)),
        kill_chain_score=float(section.get("kill_chain_score", 0.95)),
        rapid_fire_score=float(section.get("rapid_fire_score", 0.82)),
        rapid_fire_window_seconds=float(section.get("rapid_fire_window_seconds", 10.0)),
        rapid_fire_threshold=int(section.get("rapid_fire_threshold", 5)),
        suspicious_chains=chains,
    )


@lru_cache(maxsize=4)
def load_tool_patterns_map() -> ToolPatternsMap:
    """Bundled side-effect / taint-source / profile regex tables."""
    raw = _read_text("tool_patterns.toml")
    parsed = tomllib.loads(raw)
    side_effect_raw = parsed.get("side_effect")
    taint_source_raw = parsed.get("taint_source")
    profiles_raw = parsed.get("profiles")
    if not isinstance(side_effect_raw, dict) or not isinstance(taint_source_raw, dict):
        msg = "tool_patterns.toml requires [side_effect] and [taint_source]"
        raise TypeError(msg)
    if not isinstance(profiles_raw, dict):
        msg = "tool_patterns.toml requires [profiles.*] tables"
        raise TypeError(msg)
    profiles = {
        str(name): _parse_tool_profile_entry(section)
        for name, section in profiles_raw.items()
        if isinstance(section, dict)
    }
    read_only_raw = parsed.get("read_only")
    read_only = (
        _tuple_str_list(read_only_raw, "patterns") if isinstance(read_only_raw, dict) else ()
    )
    return ToolPatternsMap(
        side_effect=_tuple_str_list(side_effect_raw, "patterns"),
        taint_source=_tuple_str_list(taint_source_raw, "patterns"),
        read_only=read_only,
        profiles=profiles,
    )


@lru_cache(maxsize=4)
def load_agent_tools_map() -> AgentToolsMap:
    """Bundled agent degradation, intent, and toolchain maps."""
    raw = _read_text("agent_tools.toml")
    parsed = tomllib.loads(raw)
    high_risk_raw = parsed.get("high_risk")
    intent_raw = parsed.get("intent")
    toolchain_raw = parsed.get("toolchain")
    if not isinstance(high_risk_raw, dict):
        msg = "agent_tools.toml requires [high_risk]"
        raise TypeError(msg)
    if not isinstance(intent_raw, dict):
        msg = "agent_tools.toml requires [intent]"
        raise TypeError(msg)
    if not isinstance(toolchain_raw, dict):
        msg = "agent_tools.toml requires [toolchain]"
        raise TypeError(msg)
    benign = intent_raw.get("benign_regex")
    destructive = intent_raw.get("destructive_regex")
    if not isinstance(benign, str) or not isinstance(destructive, str):
        msg = "intent.benign_regex and intent.destructive_regex must be strings"
        raise TypeError(msg)
    return AgentToolsMap(
        high_risk_patterns=_tuple_str_list(high_risk_raw, "patterns"),
        intent_benign_regex=benign,
        intent_destructive_regex=destructive,
        toolchain=_parse_toolchain_maps(toolchain_raw),
    )


def _string_map(section: dict[str, object]) -> dict[str, str]:
    return {str(key): str(value) for key, value in section.items()}


@lru_cache(maxsize=4)
def load_normalize_maps() -> NormalizeMaps:
    """Bundled leet, homoglyph, and cross-language override maps."""
    raw = _read_text("normalize.toml")
    parsed = tomllib.loads(raw)
    leet_raw = parsed.get("leet")
    homoglyphs_raw = parsed.get("homoglyphs")
    override_raw = parsed.get("override_verbs")
    if not isinstance(leet_raw, dict):
        msg = "normalize.toml requires [leet]"
        raise TypeError(msg)
    if not isinstance(homoglyphs_raw, dict):
        msg = "normalize.toml requires [homoglyphs]"
        raise TypeError(msg)
    if not isinstance(override_raw, dict):
        msg = "normalize.toml requires [override_verbs]"
        raise TypeError(msg)
    zero_width = leet_raw.get("zero_width_chars")
    if not isinstance(zero_width, str):
        msg = "normalize.toml [leet] requires zero_width_chars"
        raise TypeError(msg)
    leet = {str(key): str(value) for key, value in leet_raw.items() if key != "zero_width_chars"}
    return NormalizeMaps(
        leet=leet,
        homoglyphs=_string_map(homoglyphs_raw),
        override_verbs=_string_map(override_raw),
        zero_width_chars=zero_width,
    )


def _read_defaults_text(resource: str) -> str:
    return resources.files("unplug.data.defaults").joinpath(resource).read_text(encoding="utf-8")


@lru_cache(maxsize=4)
def load_scanner_defaults() -> dict[str, ScannerDefaultEntry]:
    """Bundled default ScannerConfig values per scanner name."""
    raw = _read_defaults_text("scanners.toml")
    parsed = tomllib.loads(raw)
    return {
        str(name): ScannerDefaultEntry.model_validate(section)
        for name, section in parsed.items()
        if isinstance(section, dict)
    }


def default_scanner_config(name: str) -> ScannerConfig:
    """Build a ScannerConfig from data/defaults/scanners.toml."""
    from unplug.config.guard import ScannerConfig

    try:
        entry = load_scanner_defaults()[name]
    except KeyError as exc:
        msg = f"unknown scanner default: {name!r}"
        raise KeyError(msg) from exc
    return ScannerConfig(
        base_score=entry.base_score,
        enabled=entry.enabled,
        normalize=entry.normalize,
    )
