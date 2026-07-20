"""ModelProvider load concurrency."""

from __future__ import annotations

import threading
import time
from typing import Any

from unplug.ml.models import ModelProvider, ModelSpec


class _CountingProvider(ModelProvider):
    def __init__(self, spec: ModelSpec) -> None:
        super().__init__(spec)
        self.load_calls = 0

    def _do_load(self) -> None:
        self.load_calls += 1
        time.sleep(0.05)

    def _do_unload(self) -> None:
        pass

    def predict(self, inputs: Any) -> Any:
        return inputs


def test_concurrent_load_runs_do_load_once() -> None:
    provider = _CountingProvider(ModelSpec(name="count", backend="null"))
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            barrier.wait(timeout=5)
            provider.load()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert provider.load_calls == 1
    assert provider.loaded is True
