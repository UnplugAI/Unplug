"""Core enforcement layer primitives."""

from __future__ import annotations

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.secrets import SecretsRegistry, SecretsSanitizer
from unplug.core.stats import MetricsCollector
from unplug.core.disposition import (
    DispositionLabel,
    DispositionPrediction,
    DualHeadWithDisposition,
    resolve_disposition,
)
from unplug.core.taint import Tagger, TaintedText, TrustLevel

__all__ = [
    "DispositionLabel",
    "DispositionPrediction",
    "DualHeadWithDisposition",
    "ExecutionContext",
    "MetricsCollector",
    "ModelProvider",
    "ModelRegistry",
    "ModelSpec",
    "SecretsRegistry",
    "SecretsSanitizer",
    "Tagger",
    "TaintedText",
    "ToolCall",
    "TrustLevel",
    "resolve_disposition",
]
