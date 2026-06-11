"""Keep demo curated examples aligned with regex-layer expectations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from unplug import Guard

DEMO_EXAMPLES = Path(__file__).resolve().parent.parent / "demo" / "examples.json"


def _load_examples() -> dict[str, dict[str, str]]:
    with DEMO_EXAMPLES.open(encoding="utf-8") as handle:
        return json.load(handle)


@pytest.mark.parametrize("key", list(_load_examples().keys()))
def test_demo_examples_regex_scan_runs(key: str) -> None:
    examples = _load_examples()
    guard = Guard(scanners=["injection"])
    result = guard.scan(examples[key]["text"])
    assert result.latency_ms >= 0
    assert isinstance(result.safe, bool)


def test_jailbreak_example_regex_blocks() -> None:
    examples = _load_examples()
    guard = Guard(scanners=["injection"])
    result = guard.scan(examples["jailbreak_tp"]["text"])
    assert result.safe is False


def test_notinject_example_regex_allows() -> None:
    examples = _load_examples()
    guard = Guard(scanners=["injection"])
    result = guard.scan(examples["notinject_tn"]["text"])
    assert result.safe is True
