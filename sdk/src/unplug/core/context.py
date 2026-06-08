"""ExecutionContext — tracks the full agent session for context-aware enforcement."""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from unplug.core.taint import TaintedText

if TYPE_CHECKING:
    from unplug.config.policy import ScanPolicy
    from unplug.core.cache import ScanCache
    from unplug.core.secrets import SecretsRegistry


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict = Field(default_factory=dict)
    taint_sources: list[TaintedText] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    result: TaintedText | None = None
    approved: bool | None = None


class ExecutionContext:
    """Tracks session state: user intent, conversation, tool calls, and risk trajectory."""

    def __init__(
        self,
        *,
        session_id: str | None = None,
        agent_id: str | None = None,
        turn_id: int | None = None,
        document_id: str | None = None,
        user_intent: TaintedText | None = None,
        secrets_registry: SecretsRegistry | None = None,
        scan_policy: ScanPolicy | None = None,
        scan_cache: ScanCache | None = None,
    ) -> None:
        self.session_id = session_id or str(uuid.uuid4())
        self.agent_id = agent_id
        self.turn_id = turn_id
        self.document_id = document_id
        self.user_intent = user_intent
        self.conversation: list[TaintedText] = []
        self.tool_calls: list[ToolCall] = []
        self.risk_trajectory: list[float] = []
        self.secrets_registry = secrets_registry
        self.scan_policy = scan_policy
        self.scan_cache = scan_cache
        self.allowed_scanners: list[str] | None = None
        self.session_tainted: bool = False
        self.taint_triggers: list[str] = []
        self.degradation_level: int = 0

    def escalate_degradation(self, level: int) -> None:
        """Monotonic homeostasis — level only increases until session reset."""
        if level > self.degradation_level:
            self.degradation_level = level

    def reset_security_state(self) -> None:
        """Clear session taint and adaptive degradation (new trusted user turn)."""
        self.session_tainted = False
        self.taint_triggers.clear()
        self.degradation_level = 0

    def mark_session_tainted(self, reason: str) -> None:
        """Conservative session taint — side-effect tools need review after this."""
        self.session_tainted = True
        if reason and reason not in self.taint_triggers:
            self.taint_triggers.append(reason)

    @property
    def is_session_tainted(self) -> bool:
        return self.session_tainted

    def add_message(self, msg: TaintedText) -> None:
        self.conversation.append(msg)

    def add_tool_call(self, tc: ToolCall) -> None:
        self.tool_calls.append(tc)

    def update_risk(self, score: float) -> None:
        self.risk_trajectory.append(score)

    def get_risk_trend(self, window: int = 5) -> float:
        """Average slope of the last `window` risk scores. Positive = escalating."""
        scores = self.risk_trajectory[-window:]
        if len(scores) < 2:
            return 0.0
        slopes = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]
        return sum(slopes) / len(slopes)
