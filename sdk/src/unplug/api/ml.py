"""Stable ML inference API for SDK dependents.

Import span-model runtime types from here instead of ``unplug.ml.span_model``.
The heavy ML libraries are still imported lazily by ``SpanInferenceModel.load``.
"""

from __future__ import annotations

from unplug.ml import CharSpan, SpanInferenceModel, SpanPrediction, register_ml_backends

__all__ = [
    "CharSpan",
    "SpanInferenceModel",
    "SpanPrediction",
    "register_ml_backends",
]
