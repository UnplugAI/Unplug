"""Scan cache fingerprint: config that changes results must change the key."""

from __future__ import annotations

import pytest

from unplug.api.types import ScanRequest
from unplug.config.agent_policy import BoundaryConfig, DegradationConfig, TrajectoryConfig
from unplug.config.guard import GuardConfig
from unplug.guard import CACHE_IRRELEVANT_CONFIG_FIELDS, Guard


def _fingerprint(config: GuardConfig, request: ScanRequest | None = None) -> str:
    guard = Guard(config=config)
    return guard._cache_policy_fingerprint(request or ScanRequest(text="hello"))


def test_every_config_field_is_classified() -> None:
    """A new GuardConfig field must be a deliberate include or exclude.

    This is the test that keeps the fingerprint honest. It fails when someone adds
    a field to GuardConfig, forcing them to decide whether it changes scan results.
    Without it the fingerprint silently drifts out of date, which is how
    boundaries, trajectory, degradation and scan_encodings went missing.
    """
    unknown = CACHE_IRRELEVANT_CONFIG_FIELDS - set(GuardConfig.model_fields)
    assert not unknown, f"exclusion list names fields GuardConfig does not have: {unknown}"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("boundaries", BoundaryConfig(auto_wrap_untrusted=False)),
        ("trajectory", TrajectoryConfig(enabled=False)),
        ("degradation", DegradationConfig(enabled=False)),
        ("scanners", ["injection", "destructive", "secrets"]),
        ("judge_low", 0.55),
        ("strict_scanner_allowlist", True),
    ],
)
def test_result_affecting_config_changes_the_key(field: str, value: object) -> None:
    """Two Guards differing only in `field` must not share cache entries.

    boundaries, trajectory and degradation were absent from the old hand-written
    fingerprint while being passed straight into the pipelines, so two Guards
    sharing a cache could serve each other's results.
    """
    base = GuardConfig()
    other = base.model_copy(update={field: value})
    assert _fingerprint(base) != _fingerprint(other), field


def test_identical_config_gives_a_stable_key() -> None:
    assert _fingerprint(GuardConfig()) == _fingerprint(GuardConfig())


def test_excluded_config_does_not_change_the_key() -> None:
    """Connection details cannot change what a local scan returns."""
    base = GuardConfig()
    other = base.model_copy(update={"server_url": "https://example.invalid"})
    assert _fingerprint(base) == _fingerprint(other)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("block_threshold", 0.42),
        ("redact_threshold", 0.42),
        ("review_threshold", 0.42),
        ("block_coverage_ratio", 0.42),
        ("redact", False),
        ("scanners", ["injection"]),
    ],
)
def test_per_request_overrides_change_the_key(field: str, value: object) -> None:
    cfg = GuardConfig()
    base = ScanRequest(text="hello")
    other = base.model_copy(update={field: value})
    assert _fingerprint(cfg, base) != _fingerprint(cfg, other), field
