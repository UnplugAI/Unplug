"""Unplug: Unplug the bad AI."""

from __future__ import annotations

from unplug.api.messages import BlockedContent, ContentOutcome, SafeContent
from unplug.client import UnplugClient
from unplug.config import (
    GuardConfig,
    MessageConfig,
    PipelineConfig,
    ScannerConfig,
    ThresholdConfig,
)
from unplug.config import (
    load as load_config,
)
from unplug.config.limits import LimitConfig
from unplug.config.policy import ScanPolicy
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.judge import CallableJudge, JudgeContext, JudgeProvider, JudgeResult
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.privacy.secrets import SecretsRegistry
from unplug.core.runtime.logging import correlation_scope, get_correlation_id
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.exceptions import ConfigError, ServerError
from unplug.guard import Guard
from unplug.models import Action, Finding, ScanResult, Source
from unplug.scanners import ScannerRegistry
from unplug.scanners.base import BaseScanner, ModelScanner, RegexScanner

__all__ = [
    "Action",
    "BaseScanner",
    "BlockedContent",
    "CallableJudge",
    "ConfigError",
    "ContentOutcome",
    "ExecutionContext",
    "Finding",
    "Guard",
    "GuardConfig",
    "JudgeContext",
    "JudgeProvider",
    "JudgeResult",
    "LimitConfig",
    "MessageConfig",
    "MetricsCollector",
    "ModelProvider",
    "ModelRegistry",
    "ModelScanner",
    "ModelSpec",
    "PipelineConfig",
    "RegexScanner",
    "SafeContent",
    "SafeguardRegistry",
    "ScanPolicy",
    "ScanResult",
    "ScannerConfig",
    "ScannerRegistry",
    "SecretsRegistry",
    "ServerError",
    "Source",
    "Tagger",
    "TaintedText",
    "ThresholdConfig",
    "ToolCall",
    "TrustLevel",
    "UnplugClient",
    "correlation_scope",
    "get_correlation_id",
    "load_config",
]
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    # Single source of truth is pyproject.toml; avoids version drift.
    __version__ = _pkg_version("unplug-ai")
except PackageNotFoundError:  # not installed (e.g. running from a source checkout)
    __version__ = "0.5.2"


def __getattr__(name: str) -> object:
    # Deprecated alias kept importable without warning on package import.
    if name == "SafeguardRegistry":
        from unplug.scanners import registry

        return registry.SafeguardRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
