"""Reusable Guard hooks for agent frameworks (LangGraph, Agno, custom loops)."""

from __future__ import annotations

import contextlib
import dataclasses
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.api.types import ScanResult
from unplug.models import ScanRequest

_RETRIEVED_BLOCKED_PLACEHOLDER = "[RETRIEVED CONTENT BLOCKED BY UNPLUG]"
_FLATTEN_MAX_DEPTH = 6


def flatten_text(value: Any, *, _depth: int = 0) -> str:
    """Recursively flatten an arbitrary value into newline-joined scannable text.

    Agent frameworks hand the guard structured payloads — dicts, lists, Pydantic
    models, dataclasses, tool results. Scanning only ``.text`` or ``str(value)``
    can miss a secret or injection tucked in a sibling field whose string form
    hides it. This walks the structure (depth-bounded so pathological or cyclic
    objects stay safe) so every nested string is included in what gets scanned.
    """
    if value is None or _depth > _FLATTEN_MAX_DEPTH:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    if isinstance(value, (bool, int, float)):
        return str(value)
    nxt = _depth + 1
    if isinstance(value, Mapping):
        return "\n".join(flatten_text(v, _depth=nxt) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return "\n".join(flatten_text(v, _depth=nxt) for v in value)
    model_dump = getattr(value, "model_dump", None)  # Pydantic v2 model
    if callable(model_dump):
        # A failed dump falls through to the remaining strategies below.
        with contextlib.suppress(Exception):
            return flatten_text(model_dump(), _depth=nxt)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        with contextlib.suppress(Exception):
            return flatten_text(dataclasses.asdict(value), _depth=nxt)
    obj_dict = getattr(value, "__dict__", None)
    if isinstance(obj_dict, dict) and obj_dict:
        return flatten_text(obj_dict, _depth=nxt)
    return str(value)


@dataclass
class HookDecision:
    """Outcome of a Guard hook: allow, block, or review."""

    allowed: bool
    result: ScanResult
    message: str | None = None
    redacted_text: str | None = None

    @property
    def action(self) -> Action:
        return self.result.action

    @property
    def needs_review(self) -> bool:
        """True when the host should pause for operator approval (not a hard block)."""
        return self.result.action == Action.REVIEW

    @property
    def is_block(self) -> bool:
        """True on hard block (distinct from review)."""
        return not self.allowed and self.result.action == Action.BLOCK


@dataclass
class AgentHooks:
    """Drop-in Guard hooks for any agent runtime.

    Wire these into LangGraph nodes, Agno ``pre_hooks`` / tool middleware,
    or a plain ReAct loop. Tool enforcement always runs locally.
    """

    guard: Guard = field(default_factory=Guard)

    def scan_user_input(self, text: str, *, source: Source | str = Source.USER) -> HookDecision:
        result = self.guard.scan(text, source=source)
        allowed = result.action == Action.ALLOW
        if allowed:
            msg = None
        else:
            msg = f"Input blocked: {result.action.value} (risk={result.risk_score:.2f})"
        return HookDecision(
            allowed=allowed,
            result=result,
            message=msg,
            redacted_text=result.redacted_text,
        )

    def scan_agent_output(self, text: str) -> HookDecision:
        result = self.guard.scan_output(text)
        allowed = result.action == Action.ALLOW
        msg = None if allowed else f"Output blocked: {result.action.value}"
        return HookDecision(
            allowed=allowed,
            result=result,
            message=msg,
            redacted_text=result.redacted_text,
        )

    def wrap_retrieved_content(self, text: str) -> tuple[str, HookDecision]:
        wrapped = self.guard.wrap_for_context(text, source=Source.RETRIEVED)
        result = self.guard.scan(wrapped, source=Source.RETRIEVED)
        allowed = result.action == Action.ALLOW
        if allowed:
            content = result.redacted_text or wrapped
        else:
            content = result.redacted_text or _RETRIEVED_BLOCKED_PLACEHOLDER
        self.guard.notify_taint_source("web_fetch")
        msg = None if allowed else "Retrieved content blocked"
        decision = HookDecision(
            allowed=allowed,
            result=result,
            message=msg,
            redacted_text=result.redacted_text,
        )
        return content, decision

    def before_tool_call(self, name: str, args: dict[str, Any]) -> HookDecision:
        result = self.guard.check_tool_call(name, args)
        allowed = result.action == Action.ALLOW and result.safe
        msg = None
        if not allowed and result.findings:
            msg = result.findings[0].evidence
        return HookDecision(allowed=allowed, result=result, message=msg)

    def scan_request_isolated(self, text: str, *, source: Source | str = Source.USER) -> ScanResult:
        """Stateless scan: use in eval harnesses to avoid session bleed."""
        req = ScanRequest(text=text, source=source)
        return self.guard.scan_request(req, isolated=True)

    def reset_session(self) -> None:
        self.guard.reset_session_taint()
