"""ModelProvider backends for span inference."""

from __future__ import annotations

from typing import Any

from unplug.core.models import ModelProvider, ModelSpec
from unplug.ml.span_model import SpanInferenceModel
from unplug.ml.types import SpanPrediction


class TransformersSpanProvider(ModelProvider):
    """HuggingFace token-classification checkpoint for BIOES span detection."""

    def __init__(self, spec: ModelSpec) -> None:
        super().__init__(spec)
        cfg = spec.config
        path = spec.path
        if not path:
            msg = f"ModelSpec.path required for transformers_span backend ({spec.name})"
            raise ValueError(msg)
        self._engine = SpanInferenceModel(
            path,
            max_length=int(cfg.get("max_length", 256)),
            stride=int(cfg.get("stride", 64)),
            device=cfg.get("device"),
            inj_threshold=float(cfg.get("inj_threshold", 0.5)),
            doc_threshold=float(cfg["doc_threshold"]) if "doc_threshold" in cfg else None,
            local_files_only=bool(cfg.get("local_files_only", True)),
        )

    def _do_load(self) -> None:
        self._engine.load()

    def _do_unload(self) -> None:
        self._engine.unload()

    def predict(self, inputs: Any) -> SpanPrediction:
        if not isinstance(inputs, str):
            msg = "TransformersSpanProvider.predict expects str text"
            raise TypeError(msg)
        return self._engine.predict(inputs)

    @property
    def doc_threshold(self) -> float:
        return self._engine.doc_threshold
