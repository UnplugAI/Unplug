"""Core enforcement layer: flat public imports via this package."""

from __future__ import annotations

from unplug.core.agent.approval import (
    ApprovalProvider,
    NullApprovalProvider,
    build_approval_request,
)
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.normalize import EVASION_ONLY_STAGES, Normalizer, NormalizeResult
from unplug.core.normalize.encodings import (
    EncodingClassifier,
    default_encoding_classifier,
    scan_encoding_blobs,
)
from unplug.core.policy import decide_action, flagged_coverage, merge_spans, policy_from_request
from unplug.core.policy.decision import ML_ABSTAIN_SUBCATEGORY, should_invoke_ml
from unplug.core.policy.disposition import (
    DispositionLabel,
    DispositionPrediction,
    DualHeadWithDisposition,
    resolve_disposition,
)
from unplug.core.privacy import (
    HeuristicPrivacyFilter,
    NullPrivacyFilter,
    PrivacyFilterService,
    SecretsRegistry,
    SecretsSanitizer,
    build_privacy_filter,
)
from unplug.core.runtime.cache import SafePrefixState, ScanCache, merge_suffix_result
from unplug.core.runtime.logging import correlation_scope, get_correlation_id, get_logger
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION
from unplug.core.taint import Tagger, TaintedText, TrustLevel, trust_level_from_source

__all__ = [
    "EVASION_ONLY_STAGES",
    "ML_ABSTAIN_SUBCATEGORY",
    "MODEL_VERSION_LOCAL",
    "NORMALIZER_VERSION",
    "ApprovalProvider",
    "DispositionLabel",
    "DispositionPrediction",
    "DualHeadWithDisposition",
    "EncodingClassifier",
    "ExecutionContext",
    "HeuristicPrivacyFilter",
    "MetricsCollector",
    "ModelProvider",
    "ModelRegistry",
    "ModelSpec",
    "NormalizeResult",
    "Normalizer",
    "NullApprovalProvider",
    "NullPrivacyFilter",
    "PrivacyFilterService",
    "SafePrefixState",
    "ScanCache",
    "SecretsRegistry",
    "SecretsSanitizer",
    "Tagger",
    "TaintedText",
    "ToolCall",
    "TrustLevel",
    "build_approval_request",
    "build_privacy_filter",
    "correlation_scope",
    "decide_action",
    "default_encoding_classifier",
    "flagged_coverage",
    "get_correlation_id",
    "get_logger",
    "merge_spans",
    "merge_suffix_result",
    "policy_from_request",
    "resolve_disposition",
    "scan_encoding_blobs",
    "should_invoke_ml",
    "trust_level_from_source",
]
