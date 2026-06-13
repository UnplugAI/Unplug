"""Tool-call sequence analysis: kill-chain detection across session history."""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field

from unplug.config.agent_policy import ToolChainConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.data.maps_loader import load_agent_tools_map
from unplug.models import Finding

_agent_maps = load_agent_tools_map()
_toolchain = _agent_maps.toolchain

_READ_TOOLS = _toolchain.read_tools
_WRITE_TOOLS = _toolchain.write_tools
_NETWORK_TOOLS = _toolchain.network_tools
_EXEC_TOOLS = _toolchain.exec_tools
_SENSITIVE_PATH = re.compile(_toolchain.sensitive_path_regex)

_CHAIN_SCORE = _toolchain.chain_score
_KILL_CHAIN_SCORE = _toolchain.kill_chain_score
_RAPID_FIRE_SCORE = _toolchain.rapid_fire_score
_RAPID_FIRE_WINDOW_S = _toolchain.rapid_fire_window_seconds
_RAPID_FIRE_THRESHOLD = _toolchain.rapid_fire_threshold

_SUSPICIOUS_CHAINS: list[tuple[str, list[str], float]] = [
    (entry.subcategory, list(entry.sequence), entry.score) for entry in _toolchain.suspicious_chains
]


def _normalize_tool(name: str) -> str:
    return name.strip().lower().replace("-", "_")


def _token_matches(tool_name: str, token: str) -> bool:
    if token.endswith("*"):
        return tool_name.startswith(token[:-1])
    if token == "read":
        return tool_name in _READ_TOOLS or tool_name.startswith("read")
    if token == "write":
        return tool_name in _WRITE_TOOLS or "write" in tool_name
    if token == "execute":
        return tool_name in _EXEC_TOOLS or any(k in tool_name for k in ("exec", "shell", "bash"))
    if token == "http_*":
        return tool_name.startswith("http_")
    if token == "send_*":
        return tool_name.startswith("send_")
    return tool_name == token


def _contains_sequence(tools: list[str], sequence: list[str]) -> bool:
    if len(sequence) > len(tools):
        return False
    span = len(sequence)
    for i in range(len(tools) - span + 1):
        window = tools[i : i + span]
        if all(_token_matches(name, token) for name, token in zip(window, sequence, strict=True)):
            return True
    return False


def _args_text(arguments: dict) -> str:
    parts: list[str] = []
    for value in arguments.values():
        if isinstance(value, str):
            parts.append(value)
        else:
            parts.append(str(value))
    return " ".join(parts).lower()


@dataclass
class _ChainState:
    recent_timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=32))


_STATE: dict[str, _ChainState] = {}


def toolchain_findings(
    tool_call: ToolCall,
    context: ExecutionContext,
    config: ToolChainConfig | None = None,
) -> list[Finding]:
    """Flag suspicious tool sequences (read→exfil, kill chains, rapid fire)."""
    cfg = config or ToolChainConfig()
    if not cfg.enabled:
        return []

    current = _normalize_tool(tool_call.tool_name)
    history = [_normalize_tool(tc.tool_name) for tc in context.tool_calls[-cfg.history_size :]]
    chain = [*history, current]
    findings: list[Finding] = []

    for subcategory, pattern, score in _SUSPICIOUS_CHAINS:
        if _contains_sequence(chain, pattern):
            findings.append(
                Finding(
                    category="toolchain",
                    subcategory=subcategory,
                    stage="toolchain",
                    span_start=0,
                    span_end=0,
                    score=score,
                    evidence=f"Suspicious tool sequence matched: {' -> '.join(pattern)}",
                )
            )
            break

    session_key = context.session_id
    state = _STATE.setdefault(session_key, _ChainState())
    now = tool_call.timestamp or time.time()
    state.recent_timestamps.append(now)
    recent = [ts for ts in state.recent_timestamps if now - ts <= _RAPID_FIRE_WINDOW_S]
    if len(recent) > _RAPID_FIRE_THRESHOLD:
        findings.append(
            Finding(
                category="toolchain",
                subcategory="rapid_fire_tools",
                stage="toolchain",
                span_start=0,
                span_end=0,
                score=_RAPID_FIRE_SCORE,
                evidence=(
                    f"Rapid tool usage: {len(recent)} calls within "
                    f"{int(_RAPID_FIRE_WINDOW_S)}s (threshold {_RAPID_FIRE_THRESHOLD})"
                ),
            )
        )

    args = _args_text(tool_call.arguments)
    if current in _WRITE_TOOLS and _SENSITIVE_PATH.search(args):
        for prior in reversed(context.tool_calls):
            prior_name = _normalize_tool(prior.tool_name)
            if (
                prior_name in _READ_TOOLS or prior_name.startswith("read")
            ) and _SENSITIVE_PATH.search(_args_text(prior.arguments)):
                findings.append(
                    Finding(
                        category="toolchain",
                        subcategory="write_after_sensitive_read",
                        stage="toolchain",
                        span_start=0,
                        span_end=0,
                        score=_KILL_CHAIN_SCORE,
                        evidence=(
                            f"Write tool '{current}' after read on sensitive path "
                            f"(prior: '{prior_name}')"
                        ),
                    )
                )
                break

    if (
        current in _NETWORK_TOOLS
        and any(_normalize_tool(t) in _READ_TOOLS for t in history[-3:])
        and not any(f.subcategory == "read_file_http_post" for f in findings)
    ):
        findings.append(
            Finding(
                category="toolchain",
                subcategory="read_then_network",
                stage="toolchain",
                span_start=0,
                span_end=0,
                score=_CHAIN_SCORE,
                evidence=(f"Network tool '{current}' after recent read tools in session"),
            )
        )

    return findings
