"""12-stage text normalizer with span mapping for bypass detection."""

from __future__ import annotations

import base64
import re
import unicodedata

from pydantic import BaseModel, Field

from unplug.data.maps_loader import load_normalize_maps

_MAX_BASE64_DECODED_SIZE = 10_000  # 10KB max per decoded chunk


class NormalizeResult(BaseModel):
    text: str
    original: str
    offset_table: list[int] = Field(default_factory=list)
    stages_applied: list[str] = Field(default_factory=list)
    reversed_text: str | None = None

    def to_original_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
        orig_len = len(self.original)
        if not self.offset_table or norm_start >= len(self.offset_table):
            return (min(norm_start, orig_len), min(norm_end, orig_len))
        orig_start = self.offset_table[min(norm_start, len(self.offset_table) - 1)]
        orig_end_idx = min(norm_end - 1, len(self.offset_table) - 1)
        if norm_end > 0 and orig_end_idx >= 0:
            orig_end = self.offset_table[orig_end_idx] + 1
        else:
            orig_end = orig_start
        orig_start = max(0, min(orig_start, orig_len))
        orig_end = max(orig_start, min(orig_end, orig_len))
        # Include adjacent stripped invisible/bidi controls so redaction does not
        # leave U+202E / ZW chars sitting next to a matched span.
        while orig_start > 0 and self.original[orig_start - 1] in _ZERO_WIDTH_CHARS:
            orig_start -= 1
        while orig_end < orig_len and self.original[orig_end] in _ZERO_WIDTH_CHARS:
            orig_end += 1
        return (orig_start, orig_end)

    model_config = {"arbitrary_types_allowed": True}


_normalize_maps = load_normalize_maps()
_LEET_MAP: dict[str, str] = _normalize_maps.leet
_ZERO_WIDTH_CHARS = set(_normalize_maps.zero_width_chars)
_HOMOGLYPH_MAP: dict[str, str] = _normalize_maps.homoglyphs
_OVERRIDE_VERBS: dict[str, str] = _normalize_maps.override_verbs

_ENCLOSED_MAP: dict[str, str] = {}


def _build_enclosed_map() -> None:
    for offset in range(26):
        _ENCLOSED_MAP[chr(0x24B6 + offset)] = chr(ord("A") + offset)
        _ENCLOSED_MAP[chr(0x24D0 + offset)] = chr(ord("a") + offset)
    for offset in range(26):
        _ENCLOSED_MAP[chr(0xFF21 + offset)] = chr(ord("A") + offset)
        _ENCLOSED_MAP[chr(0xFF41 + offset)] = chr(ord("a") + offset)
    for offset in range(10):
        _ENCLOSED_MAP[chr(0xFF10 + offset)] = chr(ord("0") + offset)
    for offset in range(10):
        _ENCLOSED_MAP[chr(0x2460 + offset)] = str(offset + 1)


_build_enclosed_map()

_OVERRIDE_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(v) for v in _OVERRIDE_VERBS) + r")\b",
    re.IGNORECASE,
)
_COLLAPSE_SPACING_PATTERN = re.compile(r"\b([a-zA-Z])((?:\s[a-zA-Z]){2,})\b")
_CROSS_LINE_PATTERN = re.compile(r"([a-z])\n([a-z])")
_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_DOTTED_LETTERS_PATTERN = re.compile(r"\b([a-zA-Z])([.\-_|])([a-zA-Z])(?:\2[a-zA-Z]){2,}\b")
_PIPE_SPLIT_PATTERNS = (
    re.compile(r"(?<=[a-zA-Z])\|(?=[a-zA-Z])"),
    re.compile(r"(?<=[a-zA-Z])\|(?=\s)"),
    re.compile(r"(?<=\s)\|(?=[a-zA-Z])"),
)

_ALL_STAGES = [
    "unicode_tags",
    "zero_width",
    "base64",
    "fullwidth",
    "enclosed",
    "homoglyphs",
    "leet",
    "spacing",
    "cross_line",
    "markdown",
    "delimiters",
    "cross_language",
    "reversed",
]

# Stages safe for digit-heavy content (PII, amounts): excludes leet and base64.
EVASION_ONLY_STAGES = [
    "unicode_tags",
    "zero_width",
    "fullwidth",
    "enclosed",
    "homoglyphs",
    "spacing",
    "delimiters",
]


class Normalizer:
    """12-stage text normalizer that preserves span mapping to original text."""

    def __init__(self, stages: list[str] | None = None) -> None:
        self._stages = stages or list(_ALL_STAGES)

    def normalize(self, text: str) -> NormalizeResult:
        if not text:
            return NormalizeResult(text="", original="", offset_table=[], stages_applied=[])

        original = text
        offset_table = list(range(len(text)))
        stages_applied: list[str] = []
        reversed_text: str | None = None

        stage_fns = {
            "leet": _normalize_leet,
            "spacing": _collapse_spacing,
            "unicode_tags": _decode_unicode_tags,
            "zero_width": _strip_zero_width,
            "cross_line": _join_cross_line,
            "markdown": _strip_markdown,
            "homoglyphs": _normalize_homoglyphs,
            "fullwidth": _normalize_fullwidth,
            "base64": _decode_base64,
            "reversed": None,
            "enclosed": _normalize_enclosed,
            "delimiters": _strip_delimiters,
            "cross_language": _match_cross_language,
        }

        for stage_name in self._stages:
            if stage_name == "reversed":
                reversed_text = text[::-1]
                stages_applied.append("reversed")
                continue

            fn = stage_fns.get(stage_name)
            if fn is None:
                continue

            new_text, new_table = fn(text, offset_table)
            if new_text != text:
                text = new_text
                offset_table = new_table
                stages_applied.append(stage_name)

        return NormalizeResult(
            text=text,
            original=original,
            offset_table=offset_table,
            stages_applied=stages_applied,
            reversed_text=reversed_text,
        )


def _normalize_leet(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    chars = list(text)
    for i, ch in enumerate(chars):
        if ch in _LEET_MAP:
            chars[i] = _LEET_MAP[ch]
    return "".join(chars), list(offset_table)


def _collapse_spacing(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    pattern = _COLLAPSE_SPACING_PATTERN
    result_chars: list[str] = []
    result_offsets: list[int] = []
    i = 0
    for m in pattern.finditer(text):
        start, end = m.start(), m.end()
        while i < start:
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])
            i += 1
        spaced = m.group(0)
        for ch_idx in range(len(spaced)):
            ch = spaced[ch_idx]
            if ch != " ":
                result_chars.append(ch)
                result_offsets.append(offset_table[start + ch_idx])
        i = end

    while i < len(text):
        result_chars.append(text[i])
        result_offsets.append(offset_table[i])
        i += 1

    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _decode_unicode_tags(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    """Decode Unicode tag-block smuggling (U+E0020-U+E007E -> ASCII).

    Tag characters render as invisible, letting an attacker hide a full
    instruction stream inside otherwise benign text (PyRIT's unicode
    substitution converter). Printable tags map back to ASCII; the
    remaining tag-block code points (language tag, cancel) are dropped.
    """
    result_chars: list[str] = []
    result_offsets: list[int] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            result_chars.append(chr(cp - 0xE0000))
            result_offsets.append(offset_table[i])
        elif 0xE0000 <= cp <= 0xE007F:
            continue
        else:
            result_chars.append(ch)
            result_offsets.append(offset_table[i])
    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _strip_zero_width(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    result_chars: list[str] = []
    result_offsets: list[int] = []
    for i, ch in enumerate(text):
        if ch not in _ZERO_WIDTH_CHARS:
            result_chars.append(ch)
            result_offsets.append(offset_table[i])
    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _join_cross_line(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    pattern = _CROSS_LINE_PATTERN
    result_chars: list[str] = []
    result_offsets: list[int] = []
    i = 0
    for m in pattern.finditer(text):
        nl_pos = m.start() + 1
        while i < nl_pos:
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])
            i += 1
        i += 1  # skip the newline

    while i < len(text):
        result_chars.append(text[i])
        result_offsets.append(offset_table[i])
        i += 1

    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _strip_markdown(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    result_chars: list[str] = []
    result_offsets: list[int] = []
    i = 0
    n = len(text)
    while i < n:
        if (i < n - 1 and text[i : i + 2] == "**") or (i < n - 1 and text[i : i + 2] == "~~"):
            i += 2
        elif text[i] == "`" or (
            text[i] == "*" and (i == 0 or text[i - 1] in " \n") and i + 1 < n and text[i + 1] != " "
        ):
            i += 1
        elif text[i] == "#" and (i == 0 or text[i - 1] == "\n"):
            while i < n and text[i] == "#":
                i += 1
            if i < n and text[i] == " ":
                i += 1
        else:
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])
            i += 1
            continue
        continue

    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _normalize_homoglyphs(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    chars = list(text)
    changed = False
    for i, ch in enumerate(chars):
        if ch in _HOMOGLYPH_MAP:
            chars[i] = _HOMOGLYPH_MAP[ch]
            changed = True
    if not changed:
        return text, offset_table
    return "".join(chars), list(offset_table)


def _normalize_fullwidth(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    normalized = unicodedata.normalize("NFKC", text)
    if normalized == text:
        return text, offset_table

    new_offsets: list[int] = []
    orig_idx = 0
    norm_idx = 0
    orig_len = len(text)
    norm_len = len(normalized)

    while norm_idx < norm_len and orig_idx < orig_len:
        orig_char_nfkc = unicodedata.normalize("NFKC", text[orig_idx])
        chunk_len = len(orig_char_nfkc)
        for j in range(chunk_len):
            if norm_idx + j < norm_len:
                new_offsets.append(offset_table[orig_idx])
        norm_idx += chunk_len
        orig_idx += 1

    while len(new_offsets) < norm_len:
        new_offsets.append(new_offsets[-1] if new_offsets else 0)

    return normalized, new_offsets[:norm_len]


def _decode_base64(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    pattern = _BASE64_BLOB_PATTERN
    result_chars: list[str] = []
    result_offsets: list[int] = []
    last_end = 0

    for m in pattern.finditer(text):
        candidate = m.group(0)
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            if len(decoded_bytes) > _MAX_BASE64_DECODED_SIZE:
                continue
            decoded = decoded_bytes.decode("utf-8")
        except Exception:  # noqa: S112 - malformed/non-base64 candidate: skip silently
            continue

        for i in range(last_end, m.start()):
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])

        orig_start = offset_table[m.start()]
        for ch in decoded:
            result_chars.append(ch)
            result_offsets.append(orig_start)
        last_end = m.end()

    if last_end == 0:
        return text, offset_table

    for i in range(last_end, len(text)):
        result_chars.append(text[i])
        result_offsets.append(offset_table[i])

    return "".join(result_chars), result_offsets


def _normalize_enclosed(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    chars = list(text)
    changed = False
    for i, ch in enumerate(chars):
        if ch in _ENCLOSED_MAP:
            chars[i] = _ENCLOSED_MAP[ch]
            changed = True
    if not changed:
        return text, offset_table
    return "".join(chars), list(offset_table)


def _strip_delimiters(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    pattern = _DOTTED_LETTERS_PATTERN
    current_text, current_offsets = text, offset_table
    while True:
        result_chars: list[str] = []
        result_offsets: list[int] = []
        i = 0
        for m in pattern.finditer(current_text):
            start, end = m.start(), m.end()
            while i < start:
                result_chars.append(current_text[i])
                result_offsets.append(current_offsets[i])
                i += 1
            delim = m.group(2)
            segment = current_text[start:end]
            for ci, ch in enumerate(segment):
                if ch != delim:
                    result_chars.append(ch)
                    result_offsets.append(current_offsets[start + ci])
            i = end

        while i < len(current_text):
            result_chars.append(current_text[i])
            result_offsets.append(current_offsets[i])
            i += 1

        new_text = "".join(result_chars)
        if new_text == current_text:
            break
        current_text, current_offsets = new_text, result_offsets

    for pattern in _PIPE_SPLIT_PATTERNS:
        if not pattern.search(current_text):
            continue
        result_chars = []
        result_offsets = []
        for i, ch in enumerate(current_text):
            if ch == "|" and pattern.match(current_text, i):
                continue
            result_chars.append(ch)
            result_offsets.append(current_offsets[i])
        current_text = "".join(result_chars)
        current_offsets = result_offsets

    if current_text == text:
        return text, offset_table
    return current_text, current_offsets


def _match_cross_language(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    result_chars: list[str] = []
    result_offsets: list[int] = []
    last_end = 0

    for m in _OVERRIDE_PATTERN.finditer(text):
        for i in range(last_end, m.start()):
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])

        matched_word = m.group(0).lower()
        replacement = _OVERRIDE_VERBS.get(matched_word, matched_word)
        orig_start = offset_table[m.start()]

        for ch in replacement:
            result_chars.append(ch)
            result_offsets.append(orig_start)
        last_end = m.end()

    if last_end == 0:
        return text, offset_table

    for i in range(last_end, len(text)):
        result_chars.append(text[i])
        result_offsets.append(offset_table[i])

    return "".join(result_chars), result_offsets
