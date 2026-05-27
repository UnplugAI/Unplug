"""Session risk trajectory — crescendo / escalation detection."""

from __future__ import annotations

from unplug.config.agent_policy import TrajectoryConfig
from unplug.core.context import ExecutionContext
from unplug.models import Finding


def trajectory_findings(
    context: ExecutionContext,
    config: TrajectoryConfig,
) -> list[Finding]:
    """Emit findings when average risk slope is escalating across recent scans."""
    if not config.enabled:
        return []
    if len(context.risk_trajectory) < config.min_samples:
        return []

    slope = context.get_risk_trend(window=config.window)
    if slope < config.review_slope:
        return []

    if slope >= config.block_slope:
        score = 0.92
        sub = "crescendo_block"
        evidence = (
            f"Risk trajectory escalating (avg slope {slope:.3f}/step ≥ {config.block_slope}); "
            "possible crescendo attack"
        )
    else:
        score = max(config.review_slope + 0.5, 0.65)
        sub = "crescendo_review"
        evidence = (
            f"Risk trajectory rising (avg slope {slope:.3f}/step ≥ {config.review_slope}); "
            "tighten policy"
        )

    return [
        Finding(
            category="trajectory",
            subcategory=sub,
            stage="trajectory",
            span_start=0,
            span_end=0,
            score=score,
            evidence=evidence,
        )
    ]
