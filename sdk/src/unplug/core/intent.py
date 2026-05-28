"""Intent verification — side-effect tools vs benign user intent."""

from __future__ import annotations

import re

from unplug.config.agent_policy import IntentConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.models import Finding

_BENIGN_INTENT = re.compile(
    r"(?i)\b(summarize|summary|explain|describe|what\s+is|tell\s+me\s+about|"
    r"translate|overview|compare|list\s+the|how\s+does|help\s+me\s+understand)\b",
)
_DESTRUCTIVE_INTENT = re.compile(
    r"(?i)\b(delete|remove|drop|wipe|destroy|execute|run\s+command|shell|"
    r"write\s+file|deploy|transfer|send\s+money|purchase)\b",
)


def check_intent_mismatch(
    tool_call: ToolCall,
    context: ExecutionContext,
    config: IntentConfig,
    *,
    is_side_effect: bool,
) -> list[Finding]:
    """Flag side-effect tools when user intent reads informational only."""
    if not config.enabled or not is_side_effect:
        return []
    intent = context.user_intent
    if intent is None or not intent.text.strip():
        return []

    text = intent.text
    if _DESTRUCTIVE_INTENT.search(text):
        return []
    if not _BENIGN_INTENT.search(text):
        return []

    return [
        Finding(
            category="intent",
            subcategory="benign_intent_side_effect_tool",
            stage="intent_check",
            span_start=0,
            span_end=0,
            score=config.review_score,
            evidence=(
                f"Side-effect tool '{tool_call.tool_name}' conflicts with informational "
                f"user intent: {text[:120]!r}"
            ),
        )
    ]
