"""Filter tool output before an agent consumes it."""

from __future__ import annotations

from unplug.config.messages import MessageConfig
from unplug.core.runtime.scan_merge import merge_scan_results
from unplug.guard import Guard
from unplug.orchestrators.base import OrchestratorResult, scan_result_to_outcome


class ToolOutputOrchestrator:
    """Scan and sanitize strings returned from tools (scrape, search, etc.)."""

    name = "tool_output"

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        messages: MessageConfig | None = None,
    ) -> None:
        self._guard = guard or Guard()
        self._messages = messages or self._guard.config.messages

    def run(self, text: str) -> OrchestratorResult:
        # Input: injection (and related) on untrusted tool returns.
        # Output: registry secrets, canaries, leakage, PII.
        input_scan = self._guard.scan(text, source="tool_output")
        output_scan = self._guard.scan_output(text)
        scan = merge_scan_results(input_scan, output_scan)
        outcome = scan_result_to_outcome(
            scan,
            messages=self._messages,
            original_text=text,
        )
        return OrchestratorResult(outcome=outcome, scan=scan)
