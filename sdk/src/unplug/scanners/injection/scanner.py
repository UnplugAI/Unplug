"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.config.guard import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer, cached_normalize
from unplug.core.runtime.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.data.maps_loader import default_scanner_config, load_normalize_maps
from unplug.models import Finding
from unplug.scanners.base import RegexScanner
from unplug.scanners.injection.patterns import INJECTION_PATTERNS

_DEFAULT_CONFIG = default_scanner_config("injection")

# Normalization stages that can hide text. We only flag a message when the
# *characters* themselves look like abuse, not merely because a stage ran
# (ordinary Cyrillic/CJK text routinely trips homoglyph/fullwidth stages).
_EVASION_STAGES = {"zero_width", "homoglyphs", "fullwidth", "enclosed"}

_normalize_maps = load_normalize_maps()
_ZERO_WIDTH_CHARS = _normalize_maps.zero_width_chars
_HOMOGLYPH_CHARS = set(_normalize_maps.homoglyphs)

_ZERO_WIDTH_RE = re.compile("[" + re.escape(_ZERO_WIDTH_CHARS) + "]+")
# Fullwidth ASCII letters/digits (U+FF10-FF19, U+FF21-FF3A, U+FF41-FF5A) and
# enclosed/circled Latin letters (U+24B6-24CF, U+24D0-24E9) are confusable
# ASCII substitutes. Ordinary CJK punctuation (，。) and ideographs must not
# be flagged.
_CONFUSABLE_RE = re.compile(r"[\uff10-\uff19\uff21-\uff3a\uff41-\uff5a\u24b6-\u24cf\u24d0-\u24e9]+")
_WORD_RE = re.compile(r"\w+")


def _evasion_spans(original: str) -> list[tuple[int, int]]:
    """Original-text spans of genuine invisible / mixed-script evasion.

    Scoped to the offending characters rather than the whole input so redaction
    keeps the rest of the message. Plain non-English text that merely trips a
    normalization stage (whole words in Cyrillic, CJK punctuation) is not
    counted as evasion.
    """
    spans: list[tuple[int, int]] = []

    for match in _ZERO_WIDTH_RE.finditer(original):
        spans.append((match.start(), match.end()))

    for match in _CONFUSABLE_RE.finditer(original):
        spans.append((match.start(), match.end()))

    # A homoglyph is only suspicious when a non-Latin character sits inside a
    # token that is otherwise Latin: that is mixed-script smuggling ("ignоre").
    # A token written entirely in Cyrillic/Greek is ordinary foreign text.
    for match in _WORD_RE.finditer(original):
        start, end = match.start(), match.end()
        token = match.group(0)
        has_ascii_letter = any(ch.isascii() and ch.isalpha() for ch in token)
        if not has_ascii_letter:
            continue
        run_start: int | None = None
        for i, ch in enumerate(token):
            if ch in _HOMOGLYPH_CHARS:
                if run_start is None:
                    run_start = start + i
            elif run_start is not None:
                spans.append((run_start, start + i))
                run_start = None
        if run_start is not None:
            spans.append((run_start, end))

    if not spans:
        return spans

    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for span_start, span_end in spans[1:]:
        last_start, last_end = merged[-1]
        if span_start <= last_end:
            merged[-1] = (last_start, max(last_end, span_end))
        else:
            merged.append((span_start, span_end))
    return merged


class InjectionScanner(RegexScanner):
    name = "injection"
    _patterns = INJECTION_PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = cached_normalize(context, self._normalizer, text.text, cache_key="full")
        normalized = norm_result.text

        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                score = self._compute_score(subcategory, text)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=score,
                    evidence=f"Matched pattern: {subcategory}",
                    replacement=self._get_replacement(subcategory),
                )

        evasion_spans = (
            _evasion_spans(text.text)
            if _EVASION_STAGES.intersection(norm_result.stages_applied)
            else []
        )
        # When several evasion spans sit in one run (e.g. a word interleaved
        # with zero-width chars, "he\u200bl\u200bl\u200bo"), replace the whole
        # run with a single finding so redaction emits one BLOCKED tag instead
        # of one per offending character.
        if len(evasion_spans) > 1:
            evasion_spans = [(evasion_spans[0][0], evasion_spans[-1][1])]
        stages_used = ", ".join(sorted(_EVASION_STAGES.intersection(norm_result.stages_applied)))
        for span_start, span_end in evasion_spans:
            yield Finding(
                category=self.name,
                subcategory="invisible_text",
                stage="normalize",
                span_start=span_start,
                span_end=span_end,
                score=self._compute_score("invisible_text", text),
                evidence=(
                    "Invisible or mixed-script evasion detected: "
                    f"{stages_used} at span {span_start}:{span_end}"
                ),
                replacement=self._get_replacement("invisible_text"),
            )

        if norm_result.reversed_text:
            for subcategory, pattern in self._patterns:
                for _match in pattern.finditer(norm_result.reversed_text):
                    score = self._compute_score(subcategory, text)
                    yield Finding(
                        category=self.name,
                        subcategory=f"{subcategory}_reversed",
                        stage="regex",
                        span_start=0,
                        span_end=len(text.text),
                        score=score,
                        evidence=f"Reversed text matched: {subcategory}",
                        replacement=None,
                    )
