"""Deprecation shims must re-export canonical symbols and warn on import.

Flat ``unplug.core.*`` modules (and a few package-root paths) exist until v1.0
so old imports keep working. See ``sdk/MIGRATION.md``.

Shims that still need DeprecationWarning (used internally today, so warning
on import would fire for ``import unplug``):
- ``unplug.core.models`` → ``unplug.ml.models``
- ``unplug.core.extras`` → ``unplug.optional._base``
"""

from __future__ import annotations

import importlib
import sys

import pytest

# (shim_module, canonical_module, attr)
# All of these emit DeprecationWarning on (re)import.
_WARNING_SHIMS: list[tuple[str, str, str]] = [
    ("unplug.core.approval", "unplug.core.agent.approval", "ApprovalProvider"),
    ("unplug.core.asyncio_compat", "unplug.core.runtime.asyncio_compat", "run_coroutine_sync"),
    ("unplug.core.boundaries", "unplug.core.agent.boundaries", "wrap_external_content"),
    ("unplug.core.cache", "unplug.core.runtime.cache", "ScanCache"),
    ("unplug.core.canary", "unplug.core.agent.canary", "CanaryRegistry"),
    ("unplug.core.collusion", "unplug.core.agent.collusion", "collusion_findings"),
    ("unplug.core.config", "unplug.config.guard", "PipelineConfig"),
    ("unplug.core.config_loader", "unplug.config.loader", "load_from_file"),
    ("unplug.core.content", "unplug.providers.content.protocol", "ContentProvider"),
    ("unplug.core.decision", "unplug.core.policy.decision", "should_invoke_ml"),
    ("unplug.core.degradation", "unplug.core.agent.degradation", "degraded_tool_findings"),
    ("unplug.core.disposition", "unplug.core.policy.disposition", "DispositionLabel"),
    ("unplug.core.encodings", "unplug.core.normalize.encodings", "HeuristicEncodingClassifier"),
    ("unplug.core.intent", "unplug.core.agent.intent", "check_intent_mismatch"),
    ("unplug.core.limits", "unplug.config.limits", "LimitConfig"),
    ("unplug.core.logging", "unplug.core.runtime.logging", "get_correlation_id"),
    ("unplug.core.luhn", "unplug.core.privacy.luhn", "luhn_valid"),
    (
        "unplug.core.model_runtime",
        "unplug.core.runtime.model_runtime",
        "load_active_model_provider",
    ),
    ("unplug.core.secrets", "unplug.core.privacy.secrets", "SecretsRegistry"),
    (
        "unplug.core.sensitive_context",
        "unplug.core.policy.sensitive_context",
        "apply_sensitive_context_boost",
    ),
    ("unplug.core.stats", "unplug.core.runtime.stats", "MetricsCollector"),
    ("unplug.core.toolchain", "unplug.core.agent.toolchain", "toolchain_findings"),
    ("unplug.core.trajectory", "unplug.core.agent.trajectory", "trajectory_findings"),
    ("unplug.core.versions", "unplug.core.runtime.versions", "NORMALIZER_VERSION"),
    ("unplug.guard_scan", "unplug.api.results", "refresh_scan_result"),
    ("unplug.scanner", "unplug.scanners.base", "Scanner"),
    ("unplug.safeguards", "unplug.scanners", "ScannerRegistry"),
]

# Re-export only (no DeprecationWarning yet — see module docstring).
_SILENT_SHIMS: list[tuple[str, str, str]] = [
    ("unplug.core.models", "unplug.ml.models", "ModelProvider"),
    ("unplug.core.extras", "unplug.optional._base", "require_extra"),
]


def _reload_fresh(module_name: str) -> object:
    """Drop cached module so the next import re-runs module-level warn()."""
    sys.modules.pop(module_name, None)
    return importlib.import_module(module_name)


@pytest.mark.parametrize(("shim", "canonical", "attr"), _WARNING_SHIMS)
def test_deprecation_shim_warns_and_reexports(shim: str, canonical: str, attr: str) -> None:
    canon_mod = importlib.import_module(canonical)
    expected = getattr(canon_mod, attr)

    with pytest.warns(DeprecationWarning, match="deprecated"):
        shim_mod = _reload_fresh(shim)

    assert getattr(shim_mod, attr) is expected


@pytest.mark.parametrize(("shim", "canonical", "attr"), _SILENT_SHIMS)
def test_silent_reexport_shim_identity(shim: str, canonical: str, attr: str) -> None:
    # Intentionally no DeprecationWarning yet (see module docstring).
    canon_mod = importlib.import_module(canonical)
    shim_mod = importlib.import_module(shim)
    assert getattr(shim_mod, attr) is getattr(canon_mod, attr)


def test_safeguards_registry_alias_is_scanner_registry() -> None:
    with pytest.warns(DeprecationWarning, match="deprecated"):
        safeguards = _reload_fresh("unplug.safeguards")
    from unplug.scanners import ScannerRegistry

    assert safeguards.SafeguardRegistry is ScannerRegistry
    assert safeguards.ScannerRegistry is ScannerRegistry
