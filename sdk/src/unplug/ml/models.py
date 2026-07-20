"""Model loading and serving infrastructure for ML-based scanners."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import Any, Self

from pydantic import BaseModel, Field


class ModelSpec(BaseModel):
    """Describes a model to load."""

    model_config = {"frozen": True}

    name: str
    version: str = "latest"
    backend: str = "onnx"
    path: str | None = None
    repo_id: str | None = None
    config: dict = Field(default_factory=dict)


class ModelProvider(ABC):
    """Base class for all model backends (ONNX, transformers, MLX, etc.)."""

    def __init__(self, spec: ModelSpec) -> None:
        self._spec = spec
        self._loaded = False
        self._load_lock = threading.Lock()

    @property
    def spec(self) -> ModelSpec:
        return self._spec

    @property
    def loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        # Fast path: avoid lock when already loaded (predict stays lock-free).
        if self._loaded:
            return
        with self._load_lock:
            if not self._loaded:
                self._do_load()
                self._loaded = True

    def unload(self) -> None:
        with self._load_lock:
            if self._loaded:
                self._do_unload()
                self._loaded = False

    @abstractmethod
    def _do_load(self) -> None: ...

    @abstractmethod
    def _do_unload(self) -> None: ...

    @abstractmethod
    def predict(self, inputs: Any) -> Any: ...

    def predict_batch(self, batch: list[Any]) -> Generator[Any, None, None]:
        """Default: sequential prediction. Override for true batching."""
        for item in batch:
            yield self.predict(item)

    def __enter__(self) -> Self:
        self.load()
        return self

    def __exit__(self, *exc: object) -> None:
        self.unload()


class NullModelProvider(ModelProvider):
    """No-op model provider for regex-only scanners."""

    def _do_load(self) -> None:
        pass

    def _do_unload(self) -> None:
        pass

    def predict(self, inputs: Any) -> None:
        return None


class ModelRegistry:
    """Thread-safe registry that caches loaded models by name."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._providers: dict[str, ModelProvider] = {}
        self._factories: dict[str, type[ModelProvider]] = {}

    def register_backend(self, backend: str, cls: type[ModelProvider]) -> None:
        self._factories[backend] = cls

    def get(self, spec: ModelSpec) -> ModelProvider:
        with self._lock:
            key = f"{spec.name}:{spec.version}"
            if key not in self._providers:
                factory = self._factories.get(spec.backend)
                if factory is None:
                    raise ValueError(
                        f"Unknown model backend '{spec.backend}'. "
                        f"Register it with register_backend() first."
                    )
                provider = factory(spec)
                provider.load()
                self._providers[key] = provider
            return self._providers[key]

    def unload_all(self) -> None:
        with self._lock:
            for provider in self._providers.values():
                provider.unload()
            self._providers.clear()

    def loaded_models(self) -> list[str]:
        with self._lock:
            return list(self._providers.keys())


__all__ = [
    "ModelProvider",
    "ModelRegistry",
    "ModelSpec",
    "NullModelProvider",
]
