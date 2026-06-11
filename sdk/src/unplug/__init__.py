"""Unplug — Pull the plug on bad AI."""

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
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.logging import correlation_scope, get_correlation_id
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.secrets import SecretsRegistry
from unplug.core.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.guard import Guard
from unplug.models import Action, Finding, ScanResult, Source
from unplug.safeguards import SafeguardRegistry, ScannerRegistry
from unplug.safeguards.base import BaseScanner, ModelScanner, RegexScanner

__all__ = [
    "Action",
    "BaseScanner",
    "BlockedContent",
    "ContentOutcome",
    "ExecutionContext",
    "Finding",
    "Guard",
    "GuardConfig",
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
    "ScanResult",
    "ScannerConfig",
    "ScannerRegistry",
    "SecretsRegistry",
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
    __version__ = "0.2.1"
