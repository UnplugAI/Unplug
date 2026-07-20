"""Stable BYOLLM judge facades.

Import judge types from here (or top-level ``unplug``) instead of
``unplug.core.judge``.
"""

from __future__ import annotations

from unplug.core.judge import (
    JUDGE_PROMPT_TEMPLATE,
    CallableJudge,
    JudgeContext,
    JudgeProvider,
    JudgeResult,
)

__all__ = [
    "JUDGE_PROMPT_TEMPLATE",
    "CallableJudge",
    "JudgeContext",
    "JudgeProvider",
    "JudgeResult",
]
