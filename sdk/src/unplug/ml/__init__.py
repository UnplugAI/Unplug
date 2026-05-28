"""Optional ML inference (transformers / ONNX). Install with: pip install unplug-ai[ml]."""

from __future__ import annotations

from unplug.ml.registry import register_ml_backends
from unplug.ml.span_model import SpanInferenceModel
from unplug.ml.types import CharSpan, SpanPrediction

__all__ = [
    "CharSpan",
    "SpanInferenceModel",
    "SpanPrediction",
    "register_ml_backends",
]
