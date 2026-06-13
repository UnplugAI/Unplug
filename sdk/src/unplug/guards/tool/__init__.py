"""Tool-output guard: filter scrape/search results in one call."""

from __future__ import annotations

from unplug.api.messages import ContentOutcome
from unplug.config.messages import MessageConfig
from unplug.guard import Guard
from unplug.guards.base import BaseGuardFacade
from unplug.orchestrators.tool_output import ToolOutputOrchestrator


class ToolGuard(BaseGuardFacade):
    """Filter tool output before passing it to an agent."""

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        messages: MessageConfig | None = None,
    ) -> None:
        super().__init__(guard=guard, messages=messages)
        self._orchestrator = ToolOutputOrchestrator(
            self._guard,
            messages=self._messages,
        )

    def filter(self, text: str) -> ContentOutcome:
        """Scan tool output; return safe text or an agent instruction."""
        return self._orchestrator.run(text).outcome


def filter(text: str, *, guard: Guard | None = None) -> ContentOutcome:
    """One-liner: filter tool output."""
    return ToolGuard(guard=guard).filter(text)
