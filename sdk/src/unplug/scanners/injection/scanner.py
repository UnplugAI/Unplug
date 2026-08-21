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
# Mathematical alphanumeric symbols (U+1D400-U+1D7FF: bold, italic, script,
# fraktur, double-struck, sans-serif, monospace letters/digits) normalize
# straight to ASCII under NFKC, same as the confusables above. Unlike those,
# ordinary math notation strings several styled variables together ("let
# f(x) = ax + b", "define xy as the product"), so this block can't be
# unconditionally suspicious at any short run length. Benign notation tops
# out at 2 adjacent styled characters; a payload rendered in math-bold runs
# 9-12. The threshold sits between the two: below it is notation, at or
# above it is a styled word.
_MATH_ALPHANUMERIC_MIN_RUN = 4
_MATH_ALPHANUMERIC_RE = re.compile(r"[\U0001d400-\U0001d7ff]+")
_WORD_RE = re.compile(r"\w+")

# Only collapse evasion spans that sit close together (e.g. zero-width chars
# interleaved between the letters of one word). Spans separated by a long gap
# are kept as separate findings so redaction doesn't swallow ordinary text
# between two distant evasion points.
_MAX_MERGE_GAP = 3


def _merge_close(spans: list[tuple[int, int]], max_gap: int) -> list[tuple[int, int]]:
    """Merge spans that sit within max_gap of each other, in original-text order."""
    if not spans:
        return spans
    spans = sorted(spans)
    merged: list[tuple[int, int]] = [spans[0]]
    for span_start, span_end in spans[1:]:
        last_start, last_end = merged[-1]
        if span_start - last_end <= max_gap:
            merged[-1] = (last_start, max(last_end, span_end))
        else:
            merged.append((span_start, span_end))
    return merged


def _merge_whitespace_gaps(
    original: str, spans: list[tuple[int, int]], max_gap: int
) -> list[tuple[int, int]]:
    """Like _merge_close, but only across a gap that is pure whitespace.

    Real math notation packs several short styled runs against punctuation
    ("f(x)", "a+b") without a threat actor's intent; a payload chunked into
    short styled words to duck a per-run length threshold has nothing *but*
    word-boundary spaces between the chunks (a styled "the user has ..."
    split into "the", "user", "has", ...). Requiring the gap to be
    whitespace-only re-joins the latter without flattening the former.
    """
    if not spans:
        return spans
    spans = sorted(spans)
    merged: list[tuple[int, int]] = [spans[0]]
    for span_start, span_end in spans[1:]:
        last_start, last_end = merged[-1]
        gap = original[last_end:span_start]
        if span_start - last_end <= max_gap and gap.isspace():
            merged[-1] = (last_start, max(last_end, span_end))
        else:
            merged.append((span_start, span_end))
    return merged


def _evasion_spans(original: str) -> list[tuple[int, int]]:
    """Original-text spans of genuine invisible / mixed-script evasion.

    Scoped to the offending characters rather than the whole input so redaction
    keeps the rest of the message. Plain non-English text that merely trips a
    normalization stage (whole words in Cyrillic, CJK punctuation) is not
    counted as evasion, and neither is an isolated styled math symbol or a
    short run of them (ordinary notation, not a payload in disguise) — see
    `_MATH_ALPHANUMERIC_MIN_RUN` below.
    """
    spans: list[tuple[int, int]] = []

    for match in _ZERO_WIDTH_RE.finditer(original):
        spans.append((match.start(), match.end()))

    for match in _CONFUSABLE_RE.finditer(original):
        spans.append((match.start(), match.end()))

    # Below the threshold: notation like "ax" or "f(x)". At or above it: a
    # whole word rendered in styled Unicode instead of ASCII. Runs separated
    # only by whitespace are merged before the threshold is applied, not
    # after: otherwise a payload chunked into short styled words ("𝗍𝗵𝗲 𝘂𝘀𝗲𝗿
    # 𝗵𝗮𝘀 ...") stays under the per-run threshold forever, no matter how
    # long the message is. Real notation packs runs against punctuation
    # ("f(x)"), not just spaces, so it does not re-merge here.
    math_runs = [(m.start(), m.end()) for m in _MATH_ALPHANUMERIC_RE.finditer(original)]
    for span_start, span_end in _merge_whitespace_gaps(original, math_runs, _MAX_MERGE_GAP):
        if span_end - span_start >= _MATH_ALPHANUMERIC_MIN_RUN:
            spans.append((span_start, span_end))

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

    return _merge_close(spans, _MAX_MERGE_GAP)


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
