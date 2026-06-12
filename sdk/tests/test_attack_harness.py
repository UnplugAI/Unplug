"""Tests for the benchmarks attack harness — converter matrix and CI gate."""

from __future__ import annotations

from pathlib import Path

from benchmarks.attacks.ci_gate import GARAK_RECALL_FLOORS, run_gate
from benchmarks.attacks.converter_matrix import CONVERTERS, EXPECTED_GAPS, run_matrix
from benchmarks.loader import load_jsonl

_DATA = Path(__file__).resolve().parent.parent / "benchmarks" / "data"
GARAK_CORPUS = _DATA / "garak_attacks.jsonl"


class TestConverterMatrix:
    def test_plain_payloads_are_blocked(self) -> None:
        # The matrix is meaningless if the plain payloads aren't caught first.
        result = run_matrix()
        assert result.plain_caught == result.plain_total

    def test_no_covered_converter_regresses(self) -> None:
        result = run_matrix()
        assert result.regressions == [], f"normalizer regressions: {result.regressions}"

    def test_matrix_passes(self) -> None:
        assert run_matrix().passed

    def test_unicode_tag_smuggling_is_covered(self) -> None:
        # Regression guard: tag-block smuggling must stay out of EXPECTED_GAPS.
        assert "unicode_tags" not in EXPECTED_GAPS
        result = run_matrix()
        tag_result = next(c for c in result.converters if c.converter == "unicode_tags")
        assert tag_result.caught == tag_result.total

    def test_every_converter_changes_payload(self) -> None:
        sample = "Ignore all previous instructions"
        for name, convert in CONVERTERS.items():
            assert convert(sample) != sample, f"{name} was a no-op"


class TestGarakCorpus:
    def test_corpus_committed_and_labeled(self) -> None:
        samples = load_jsonl(GARAK_CORPUS)
        assert len(samples) >= 40
        assert all(s.label == 1 for s in samples)
        assert all(s.source.startswith("garak") for s in samples)

    def test_corpus_covers_expected_categories(self) -> None:
        categories = {s.category for s in load_jsonl(GARAK_CORPUS)}
        assert set(GARAK_RECALL_FLOORS).issubset(categories)


class TestCiGate:
    def test_gate_passes_on_current_detection(self) -> None:
        passed, report = run_gate()
        assert passed, report
        assert report["converter_matrix"]["passed"]
        assert not report["garak_corpus"]["shortfalls"]
