"""Multi-agent collusion detection — pair frequency and cross-agent exfil."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from unplug.config.agent_policy import CollusionConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.toolchain import (
    _NETWORK_TOOLS,
    _READ_TOOLS,
    _SENSITIVE_PATH,
    _args_text,
    _normalize_tool,
)
from unplug.models import Finding

_AGENT_MSG_TOOLS = frozenset(
    {
        "message_agent",
        "instruct_agent",
        "send_message",
        "notify_agent",
        "delegate",
    }
)
_PAIR_SCORE = 0.90
_CROSS_AGENT_SCORE = 0.93


@dataclass
class _PairState:
    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=128))


@dataclass
class _SensitiveRead:
    agent_id: str
    timestamp: float
    path_hint: str


@dataclass
class _SessionCollusionState:
    pair_events: dict[tuple[str, str], _PairState] = field(default_factory=dict)
    sensitive_reads: deque[_SensitiveRead] = field(default_factory=lambda: deque(maxlen=64))


_STATE: dict[str, _SessionCollusionState] = {}


def _session_state(session_id: str) -> _SessionCollusionState:
    return _STATE.setdefault(session_id, _SessionCollusionState())


def _prune_timestamps(timestamps: deque[float], *, now: float, window_s: float) -> None:
    cutoff = now - window_s
    while timestamps and timestamps[0] < cutoff:
        timestamps.popleft()


def record_agent_pair(
    source_agent: str,
    target_agent: str,
    *,
    session_id: str,
    config: CollusionConfig,
) -> bool:
    """Record an agent-to-agent message; return True if pair exceeds threshold."""
    if not config.enabled or not source_agent or not target_agent:
        return False
    if source_agent == target_agent:
        return False

    state = _session_state(session_id)
    pair = (source_agent, target_agent)
    now = time.time()
    pair_state = state.pair_events.setdefault(pair, _PairState())
    _prune_timestamps(pair_state.timestamps, now=now, window_s=config.window_seconds)
    pair_state.timestamps.append(now)
    return len(pair_state.timestamps) > config.pair_message_threshold


def record_sensitive_read(
    agent_id: str,
    tool_call: ToolCall,
    *,
    session_id: str,
    config: CollusionConfig,
) -> None:
    if not config.enabled or not agent_id:
        return
    args = _args_text(tool_call.arguments)
    if not _SENSITIVE_PATH.search(args):
        return
    state = _session_state(session_id)
    state.sensitive_reads.append(
        _SensitiveRead(
            agent_id=agent_id,
            timestamp=tool_call.timestamp or time.time(),
            path_hint=args[:80],
        )
    )


def collusion_findings(
    tool_call: ToolCall,
    context: ExecutionContext,
    config: CollusionConfig | None = None,
) -> list[Finding]:
    """Flag high-frequency agent pairs and cross-agent read→exfil patterns."""
    cfg = config or CollusionConfig()
    if not cfg.enabled:
        return []

    findings: list[Finding] = []
    agent_id = context.agent_id or "unknown"
    tool_name = _normalize_tool(tool_call.tool_name)
    now = tool_call.timestamp or time.time()
    session_id = context.session_id

    if tool_name in _AGENT_MSG_TOOLS:
        target = (
            tool_call.arguments.get("agent_id")
            or tool_call.arguments.get("to")
            or tool_call.arguments.get("recipient")
            or tool_call.arguments.get("target")
        )
        if target and agent_id != "unknown":
            target_str = str(target)
            exceeded = record_agent_pair(
                agent_id,
                target_str,
                session_id=session_id,
                config=cfg,
            )
            if exceeded:
                pair_state = _session_state(session_id).pair_events[(agent_id, target_str)]
                count = len(pair_state.timestamps)
                findings.append(
                    Finding(
                        category="collusion",
                        subcategory="high_frequency_pair",
                        stage="collusion",
                        span_start=0,
                        span_end=0,
                        score=_PAIR_SCORE,
                        evidence=(
                            f"Agents '{agent_id}' → '{target_str}' exchanged {count} messages "
                            f"within {int(cfg.window_seconds)}s "
                            f"(threshold {cfg.pair_message_threshold})"
                        ),
                    )
                )

    read_tools = _READ_TOOLS | frozenset({"read_all_files"})
    if tool_name in read_tools or tool_name.startswith("read"):
        record_sensitive_read(agent_id, tool_call, session_id=session_id, config=cfg)

    if tool_name in _NETWORK_TOOLS and agent_id != "unknown":
        state = _session_state(session_id)
        cutoff = now - cfg.cross_agent_window_seconds
        for prior in reversed(state.sensitive_reads):
            if prior.timestamp < cutoff:
                break
            if prior.agent_id != agent_id:
                findings.append(
                    Finding(
                        category="collusion",
                        subcategory="cross_agent_exfil",
                        stage="collusion",
                        span_start=0,
                        span_end=0,
                        score=_CROSS_AGENT_SCORE,
                        evidence=(
                            f"Agent '{agent_id}' used network tool '{tool_name}' after "
                            f"agent '{prior.agent_id}' read sensitive data "
                            f"({prior.path_hint[:40]!r})"
                        ),
                    )
                )
                break

    return findings
