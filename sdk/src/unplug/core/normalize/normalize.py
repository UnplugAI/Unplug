"""12-stage text normalizer with span mapping for bypass detection."""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata

from pydantic import BaseModel, Field

from unplug.core.pattern_loader import injection_patterns
from unplug.data.maps_loader import load_normalize_maps

_MAX_BASE64_DECODED_SIZE = 10_000  # 10KB max per decoded chunk
_MIN_BASE64_BLOB_LEN = 8
_MIN_ROT13_BLOB_LEN = 20
_INJECTION_PATTERNS = injection_patterns()


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
        while orig_start > 0 and _is_invisible_format(self.original[orig_start - 1]):
            orig_start -= 1
        while orig_end < orig_len and _is_invisible_format(self.original[orig_end]):
            orig_end += 1
        return (orig_start, orig_end)

    model_config = {"arbitrary_types_allowed": True}


_normalize_maps = load_normalize_maps()
_LEET_MAP: dict[str, str] = _normalize_maps.leet
# Bundled allowlist (legacy / docs); stripping uses Unicode categories instead.
_ZERO_WIDTH_CHARS = set(_normalize_maps.zero_width_chars)
# Default-ignorable Mn used for grapheme smuggling (not Cf).
_EXTRA_INVISIBLE_CHARS = frozenset({"\u034f"})  # COMBINING GRAPHEME JOINER
# When both alpha runs around a glue point are at least this long, insert a
# space instead of deleting the delimiter so `\s+` patterns still match.
_WORD_GLUE_MIN_RUN = 3
_HOMOGLYPH_MAP: dict[str, str] = _normalize_maps.homoglyphs
_OVERRIDE_VERBS: dict[str, str] = _normalize_maps.override_verbs


def _is_invisible_format(ch: str) -> bool:
    """True for format/invisible code points that should be stripped.

    Uses Unicode category Cf (format) rather than a fixed allowlist so newly
    assigned invisible operators (e.g. U+2061-U+2064) are covered. Also strips
    U+034F (Mn, combining grapheme joiner), which is default-ignorable but not
    Cf. Does not strip Cc (keeps newlines/tabs) or other Mn (keeps accents).
    """
    return unicodedata.category(ch) == "Cf" or ch in _EXTRA_INVISIBLE_CHARS


def _ascii_alpha_run_len_before(text: str, idx: int) -> int:
    """Length of the ASCII alphabetic run ending at idx - 1."""
    n = 0
    i = idx - 1
    while i >= 0 and text[i].isascii() and text[i].isalpha():
        n += 1
        i -= 1
    return n


def _ascii_alpha_run_len_after(text: str, idx: int) -> int:
    """Length of the ASCII alphabetic run starting at idx + 1."""
    n = 0
    i = idx + 1
    length = len(text)
    while i < length and text[i].isascii() and text[i].isalpha():
        n += 1
        i += 1
    return n


def _should_insert_word_boundary(text: str, delim_idx: int) -> bool:
    """Insert a space when gluing would concatenate two word-length tokens."""
    left = _ascii_alpha_run_len_before(text, delim_idx)
    right = _ascii_alpha_run_len_after(text, delim_idx)
    return left >= _WORD_GLUE_MIN_RUN and right >= _WORD_GLUE_MIN_RUN


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
_BASE64_CHARSET = r"A-Za-z0-9+/\-_="
_BASE64_CONTIGUOUS_PATTERN = re.compile(rf"[{_BASE64_CHARSET}]{{{_MIN_BASE64_BLOB_LEN},}}")
_BASE64_CHUNK_TOKEN = re.compile(rf"[{_BASE64_CHARSET}]+")
_BASE64_BLOB_PATTERN = _BASE64_CONTIGUOUS_PATTERN
_BASE64_WS_COLLAPSE = re.compile(r"\s+")
_BASE64_ASSIGNMENT_PREFIX = re.compile(r"^[a-z]+=")
_ROT13_BLOB_PATTERN = re.compile(r"\b[a-zA-Z]+(?: [a-zA-Z]+)+\b")
_ENGLISH_WORD_HINT = re.compile(
    r"\b(?:"
    r"the|and|for|that|this|with|from|please|your|have|are|was|were|been|will|"
    r"would|could|should|about|into|what|when|where|which|their|there|other|"
    r"some|than|them|then|these|those|such|every|after|before|being|under|"
    r"while|during|without|within|against|between|through|summary|summarize|"
    r"quarterly|finance|weather|report|team|today|help|send|make|take|"
    r"give|find|know|think|want|need|work|look|good|great|best|"
    r"ignore|previous|instructions"
    r")\b",
    re.IGNORECASE,
)
_DOTTED_LETTERS_PATTERN = re.compile(r"\b([a-zA-Z])([.\-_|])([a-zA-Z])(?:\2[a-zA-Z]){2,}\b")
_PIPE_SPLIT_PATTERNS = (
    re.compile(r"(?<=[a-zA-Z])\|(?=[a-zA-Z])"),
    re.compile(r"(?<=[a-zA-Z])\|(?=\s)"),
    re.compile(r"(?<=\s)\|(?=[a-zA-Z])"),
)
# Digit-leet must not rewrite hex/unicode escape payloads: \x69 / \u0069 contain
# leet-mapped digits (0,1,4,5,7) that would corrupt the escape detectors.
_HEX_ESCAPE_SPAN = re.compile(r"\\x[0-9a-fA-F]{2}", re.IGNORECASE)
_UNICODE_ESCAPE_SPAN = re.compile(r"\\u[0-9a-fA-F]{4}")

_ALL_STAGES = [
    "unicode_tags",
    "zero_width",
    "base64",
    "rot13",
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
            "rot13": _decode_rot13,
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


def _leet_protected_mask(text: str) -> list[bool]:
    """True for chars inside \\xNN / \\uNNNN spans that digit-leet must skip."""
    protected = [False] * len(text)
    for pattern in (_HEX_ESCAPE_SPAN, _UNICODE_ESCAPE_SPAN):
        for match in pattern.finditer(text):
            for i in range(match.start(), match.end()):
                protected[i] = True
    return protected


def _normalize_leet(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    chars = list(text)
    protected = _leet_protected_mask(text)
    for i, ch in enumerate(chars):
        if protected[i]:
            continue
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
        if not _is_invisible_format(ch):
            result_chars.append(ch)
            result_offsets.append(offset_table[i])
    new_text = "".join(result_chars)
    if new_text == text:
        return text, offset_table
    return new_text, result_offsets


def _join_cross_line(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    """Join letter\\nletter splits; preserve spaces between word-length tokens."""
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
        if _should_insert_word_boundary(text, nl_pos):
            result_chars.append(" ")
            result_offsets.append(offset_table[nl_pos])
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


def _rot13(text: str) -> str:
    return codecs.decode(text, "rot13")


def _english_word_hint_count(text: str) -> int:
    return len(_ENGLISH_WORD_HINT.findall(text))


def _is_plausible_decoded_payload(decoded: str) -> bool:
    """Skip decoded blobs that are not meaningful UTF-8 text (e.g. null-byte runs)."""
    if not decoded.strip():
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t\r")
    return printable / len(decoded) >= 0.8


def _is_likely_rot13_payload(raw: str, decoded: str) -> bool:
    """Heuristic: ROT13 ciphertext has fewer English hints than its plaintext."""
    if not _is_plausible_decoded_payload(decoded):
        return False
    if len(decoded) > _MAX_BASE64_DECODED_SIZE:
        return False
    return _english_word_hint_count(decoded) > _english_word_hint_count(raw)


def _decoded_matches_injection(decoded: str) -> bool:
    return any(pattern.search(decoded) for _subcategory, pattern in _INJECTION_PATTERNS)


def _is_base64_chunk_token(token: str) -> bool:
    """Reject lowercase word tokens that share the base64 alphabet."""
    return not (len(token) >= 3 and token.isalpha() and token.islower())


def _iter_base64_blob_spans(text: str) -> list[tuple[int, int, str]]:
    """Yield non-overlapping contiguous and whitespace-chunked base64 spans."""
    spans: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []

    def _overlaps(start: int, end: int) -> bool:
        return any(not (end <= lo or start >= hi) for lo, hi in occupied)

    def _add(start: int, end: int) -> None:
        raw = text[start:end]
        if len(_collapse_base64_whitespace(raw)) < _MIN_BASE64_BLOB_LEN:
            return
        if _overlaps(start, end):
            return
        spans.append((start, end, raw))
        occupied.append((start, end))

    for match in _BASE64_CONTIGUOUS_PATTERN.finditer(text):
        _add(match.start(), match.end())

    idx = 0
    length = len(text)
    while idx < length:
        token_match = _BASE64_CHUNK_TOKEN.match(text, idx)
        if token_match is None or not _is_base64_chunk_token(token_match.group(0)):
            idx += 1
            continue

        start = idx
        end = token_match.end()
        token_count = 1
        scan = end
        while scan < length:
            ws = scan
            while ws < length and text[ws] in " \t\r\n":
                ws += 1
            if ws >= length:
                break
            next_token = _BASE64_CHUNK_TOKEN.match(text, ws)
            if next_token is None or not _is_base64_chunk_token(next_token.group(0)):
                break
            token_count += 1
            end = next_token.end()
            scan = end

        if token_count >= 2:
            _add(start, end)
            idx = end
        else:
            idx += 1

    spans.sort(key=lambda item: item[0])
    return spans


_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")


def _collapse_base64_whitespace(raw: str) -> str:
    return _BASE64_WS_COLLAPSE.sub("", raw)


def _try_decode_base64_payload(raw: str) -> str | None:
    """Decode standard or URL-safe base64 after collapsing internal whitespace."""
    collapsed = _collapse_base64_whitespace(raw)
    assignment = _BASE64_ASSIGNMENT_PREFIX.match(collapsed)
    if assignment:
        collapsed = collapsed[assignment.end() :]
    if len(collapsed) < _MIN_BASE64_BLOB_LEN:
        return None
    padded = collapsed + "=" * ((4 - len(collapsed) % 4) % 4)
    # urlsafe_b64decode takes no validate= keyword, so translating the URL-safe
    # alphabet back to the standard one keeps both variants strictly validated.
    candidates = (padded, padded.translate(_URLSAFE_TO_STANDARD))
    for candidate in candidates:
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            if len(decoded_bytes) > _MAX_BASE64_DECODED_SIZE:
                return None
            decoded = decoded_bytes.decode("utf-8")
        except Exception:  # noqa: S112 - malformed/non-base64 candidate: skip silently
            continue
        if _is_plausible_decoded_payload(decoded):
            return decoded
    return None


def _decode_rot13(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    pattern = _ROT13_BLOB_PATTERN
    result_chars: list[str] = []
    result_offsets: list[int] = []
    last_end = 0

    for m in pattern.finditer(text):
        raw = m.group(0)
        if len(raw) < _MIN_ROT13_BLOB_LEN:
            continue
        if _english_word_hint_count(raw) >= 2:
            continue
        decoded = _rot13(raw)
        if not _is_likely_rot13_payload(raw, decoded):
            continue
        if not _decoded_matches_injection(decoded):
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


def _decode_base64(text: str, offset_table: list[int]) -> tuple[str, list[int]]:
    result_chars: list[str] = []
    result_offsets: list[int] = []
    last_end = 0

    for start, end, raw in _iter_base64_blob_spans(text):
        decoded = _try_decode_base64_payload(raw)
        if decoded is None:
            continue
        if not _decoded_matches_injection(decoded):
            continue

        for i in range(last_end, start):
            result_chars.append(text[i])
            result_offsets.append(offset_table[i])

        orig_start = offset_table[start]
        for ch in decoded:
            result_chars.append(ch)
            result_offsets.append(orig_start)
        last_end = end

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
                # Word|word → space so `\s+` patterns still match; letter|letter
                # (short runs) still glue for dotted/pipe letter-split evasion.
                if _should_insert_word_boundary(current_text, i):
                    result_chars.append(" ")
                    result_offsets.append(current_offsets[i])
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
