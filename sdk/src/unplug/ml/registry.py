"""Register optional ML backends on a ModelRegistry."""

from __future__ import annotations

from unplug.core.models import ModelRegistry, NullModelProvider
from unplug.ml.providers import TransformersSpanProvider


def register_ml_backends(registry: ModelRegistry) -> None:
    registry.register_backend("null", NullModelProvider)
    registry.register_backend("transformers_span", TransformersSpanProvider)
