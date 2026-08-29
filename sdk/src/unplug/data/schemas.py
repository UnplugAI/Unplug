"""Pydantic schemas for packaged data maps (tool/agent TOML)."""

from __future__ import annotations

from pydantic import BaseModel


class ToolProfileMapEntry(BaseModel):
    model_config = {"frozen": True}

    blocked_patterns: tuple[str, ...] = ()
    allowed_patterns: tuple[str, ...] | None = None


class ToolPatternsMap(BaseModel):
    model_config = {"frozen": True}

    side_effect: tuple[str, ...]
    taint_source: tuple[str, ...]
    read_only: tuple[str, ...] = ()
    profiles: dict[str, ToolProfileMapEntry]


class SuspiciousChainEntry(BaseModel):
    model_config = {"frozen": True}

    subcategory: str
    sequence: tuple[str, ...]
    score: float


class ToolchainMaps(BaseModel):
    model_config = {"frozen": True}

    read_tools: frozenset[str]
    write_tools: frozenset[str]
    network_tools: frozenset[str]
    exec_tools: frozenset[str]
    sensitive_path_regex: str
    chain_score: float = 0.88
    kill_chain_score: float = 0.95
    rapid_fire_score: float = 0.82
    rapid_fire_window_seconds: float = 10.0
    rapid_fire_threshold: int = 5
    suspicious_chains: tuple[SuspiciousChainEntry, ...] = ()


class AgentToolsMap(BaseModel):
    model_config = {"frozen": True}

    high_risk_patterns: tuple[str, ...]
    intent_benign_regex: str
    intent_destructive_regex: str
    toolchain: ToolchainMaps


class NormalizeMaps(BaseModel):
    model_config = {"frozen": True}

    leet: dict[str, str]
    homoglyphs: dict[str, str]
    override_verbs: dict[str, str]
    zero_width_chars: str


class ScannerDefaultEntry(BaseModel):
    model_config = {"frozen": True}

    base_score: float
    enabled: bool = True
    normalize: bool = False
