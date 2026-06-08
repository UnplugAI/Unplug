"""Encoding probe battery — base64 extract → decode → classify."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from unplug import Guard
from unplug.config.loader import load
from unplug.core.encodings import (
    HeuristicEncodingClassifier,
    SpanModelEncodingClassifier,
    default_encoding_classifier,
    iter_base64_blobs,
    scan_encoding_blobs,
)
from unplug.core.model_runtime import load_active_model_provider
from unplug.ml.validation import resolve_validation_checkpoint

ROOT = Path(__file__).resolve().parents[3]
PROBES = ROOT / "repos/unplug_exp/configs/encoding_probe_queries.json"


def _checkpoint() -> Path | None:
    env = os.environ.get("UNPLUG_TEST_CHECKPOINT")
    if env and Path(env).is_dir():
        return Path(env)
    return resolve_validation_checkpoint(require_weights=False)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _materialize(probe: dict) -> str:
    fmt = probe.get("format", "literal")
    if fmt == "literal":
        return str(probe["text"])
    inner = str(probe["inner_text"])
    blob = _b64(inner)
    wrapper = str(probe.get("wrapper", "{blob}"))
    return wrapper.format(blob=blob)


@pytest.fixture(scope="module")
def probes() -> list[dict]:
    if not PROBES.is_file():
        pytest.skip("encoding probes file missing")
    return json.loads(PROBES.read_text(encoding="utf-8"))


class TestEncodingProbeMaterialization:
    def test_probe_file_has_cases(self, probes: list[dict]) -> None:
        assert len(probes) >= 8
        ids = {p["id"] for p in probes}
        assert "b64_linkedin_flan" in ids
        assert "b64_benign_weather" in ids


class TestHeuristicEncodingProbes:
    def test_direct_ignore_detected(self, probes: list[dict]) -> None:
        probe = next(p for p in probes if p["id"] == "b64_direct_ignore")
        text = _materialize(probe)
        findings = scan_encoding_blobs(text, classifier=HeuristicEncodingClassifier())
        assert findings
        assert findings[0].stage == "encoding"

    def test_linkedin_flan_not_detected_by_heuristic(self, probes: list[dict]) -> None:
        probe = next(p for p in probes if p["id"] == "b64_linkedin_flan")
        text = _materialize(probe)
        assert scan_encoding_blobs(text, classifier=HeuristicEncodingClassifier()) == []

    @pytest.mark.parametrize(
        "probe_id",
        ["b64_benign_weather", "b64_benign_recipe", "api_key_not_blob"],
    )
    def test_benign_probes_no_finding(self, probes: list[dict], probe_id: str) -> None:
        probe = next(p for p in probes if p["id"] == probe_id)
        text = _materialize(probe)
        assert scan_encoding_blobs(text) == []


@pytest.mark.skipif(_checkpoint() is None, reason="checkpoint not available")
class TestSpanModelEncodingProbes:
    @pytest.fixture
    def model_classifier(self) -> SpanModelEncodingClassifier:
        pytest.importorskip("torch")
        ckpt = _checkpoint()
        assert ckpt is not None
        os.environ["UNPLUG_ACTIVE_MODEL"] = "tiny"
        os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
        cfg = load()
        provider = load_active_model_provider(cfg)
        assert provider is not None
        return SpanModelEncodingClassifier(provider)

    def test_linkedin_flan_detected_after_decode(
        self, probes: list[dict], model_classifier
    ) -> None:
        probe = next(p for p in probes if p["id"] == "b64_linkedin_flan")
        text = _materialize(probe)
        findings = scan_encoding_blobs(text, classifier=model_classifier)
        assert len(findings) == 1
        assert "span_model" in findings[0].evidence

    def test_benign_weather_stays_clean(self, probes: list[dict], model_classifier) -> None:
        probe = next(p for p in probes if p["id"] == "b64_benign_weather")
        text = _materialize(probe)
        assert scan_encoding_blobs(text, classifier=model_classifier) == []

    def test_default_classifier_uses_model_when_available(self, probes: list[dict]) -> None:
        pytest.importorskip("torch")
        ckpt = _checkpoint()
        assert ckpt is not None
        os.environ["UNPLUG_ACTIVE_MODEL"] = "tiny"
        os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
        cfg = load()
        provider = load_active_model_provider(cfg)
        assert provider is not None
        backend = default_encoding_classifier(provider)
        probe = next(p for p in probes if p["id"] == "b64_linkedin_flan")
        text = _materialize(probe)
        findings = scan_encoding_blobs(text, classifier=backend)
        assert findings


@pytest.mark.skipif(_checkpoint() is None, reason="checkpoint not available")
class TestGuardEncodingIntegration:
    @pytest.fixture
    def guard(self) -> Guard:
        pytest.importorskip("torch")
        ckpt = _checkpoint()
        assert ckpt is not None
        os.environ["UNPLUG_ACTIVE_MODEL"] = "tiny"
        os.environ["UNPLUG_MODEL_PATH"] = str(ckpt)
        return Guard(config=load(), mode="local")

    def test_guard_blocks_b64_linkedin_flan(self, guard: Guard, probes: list[dict]) -> None:
        probe = next(p for p in probes if p["id"] == "b64_linkedin_flan")
        text = _materialize(probe)
        result = guard.scan(text)
        assert not result.safe
        assert any(f.stage == "encoding" for f in result.findings)

    def test_guard_allows_b64_benign_weather(self, guard: Guard, probes: list[dict]) -> None:
        probe = next(p for p in probes if p["id"] == "b64_benign_weather")
        text = _materialize(probe)
        result = guard.scan(text)
        assert result.safe

    def test_blob_spans_map_to_original(self, probes: list[dict]) -> None:
        probe = next(p for p in probes if p["id"] == "b64_direct_ignore")
        text = _materialize(probe)
        blobs = iter_base64_blobs(text)
        assert len(blobs) == 1
        assert text[blobs[0].start : blobs[0].end] == blobs[0].raw
