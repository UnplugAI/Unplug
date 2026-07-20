"""Stable policy helpers for SDK dependents.

This module is the public import surface for scan-policy decisions. Dependents
should import from here instead of ``unplug.core.policy``.
"""

from __future__ import annotations

from unplug.config.policy import DecisionMode, MlGateConfig, RedactionMode, ScanPolicy
from unplug.core.policy import (
    decide_action,
    flagged_coverage,
    is_result_safe,
    merge_spans,
    policy_from_request,
)

__all__ = [
    "DecisionMode",
    "MlGateConfig",
    "RedactionMode",
    "ScanPolicy",
    "decide_action",
    "flagged_coverage",
    "is_result_safe",
    "merge_spans",
    "policy_from_request",
]
