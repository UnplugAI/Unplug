"""Extract encoding blobs from original text (Base64 and ROT13 v1)."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Protocol

from unplug.api.types import Finding
from unplug.core.normalize.normalize import (
    _BASE64_BLOB_PATTERN,
    _MIN_ROT13_BLOB_LEN,
    _ROT13_BLOB_PATTERN,
    Normalizer,
    _english_word_hint_count,
    _is_likely_rot13_payload,
    _iter_base64_blob_spans,
    _rot13,
    _try_decode_base64_payload,
)
from unplug.core.pattern_loader import injection_patterns

# Core-owned injection patterns (same data the injection scanner loads), imported
# directly from the loader so core/ never depends on scanners/ (layering rule).
INJECTION_PATTERNS = injection_patterns()

if TYPE_CHECKING:
    from unplug.core.models import ModelProvider

# Same pattern as normalize._decode_base64.
BASE64_BLOB_PATTERN = _BASE64_BLOB_PATTERN
# Same pattern as normalize._decode_rot13.
ROT13_BLOB_PATTERN = _ROT13_BLOB_PATTERN
_SECRET_CONTEXT_BEFORE = re.compile(
    r"(?i)(?:"
    r"(?:sk|pk|ghp|gho|ghu|ghs|ghr|AKIA|eyJ)[-_]?|"
    r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?"
    r")$",
)


def _is_probable_base64_blob(text: str, start: int, raw: str) -> bool:
    """Skip blobs that are likely API tokens/secrets, not encoded payloads."""
    _ = raw
    prefix = text[max(0, start - 32) : start]
    return _SECRET_CONTEXT_BEFORE.search(prefix) is None


def _is_probable_rot13_blob(raw: str) -> bool:
    """Skip alphabetic runs that already look like plain English."""
    if len(raw) < _MIN_ROT13_BLOB_LEN:
        return False
    if _english_word_hint_count(raw) >= 2:
        return False
    decoded = _rot13(raw)
    return _is_likely_rot13_payload(raw, decoded)


class EncodingBlob:
    """A contiguous encoding region in the original string."""

    __slots__ = ("decoded", "end", "raw", "start")

    def __init__(
        self,
        *,
        start: int,
        end: int,
        raw: str,
        decoded: str | None,
    ) -> None:
        self.start = start
        self.end = end
        self.raw = raw
        self.decoded = decoded


class EncodingClassifier(Protocol):
    """Classify decoded payload (Prompt Guard on server; heuristic in SDK v1)."""

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]: ...


class HeuristicEncodingClassifier:
    """v1 stand-in: injection regex on decoded UTF-8."""

    def __init__(self, *, base_score: float = 0.85) -> None:
        self._base_score = base_score

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]:
        for subcategory, pattern in INJECTION_PATTERNS:
            if pattern.search(decoded):
                return True, self._base_score, subcategory
        return False, 0.0, ""


class SpanModelEncodingClassifier:
    """Decode-then-classify: run span model on resolved UTF-8 payload."""

    def __init__(
        self,
        model: ModelProvider,
        *,
        inj_threshold: float = 0.5,
        base_score: float = 0.85,
    ) -> None:
        self._model = model
        self._inj_threshold = inj_threshold
        self._base_score = base_score
        self._normalizer = Normalizer()

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]:
        if not self._model.loaded:
            self._model.load()
        norm = self._normalizer.normalize(decoded)
        prediction = self._model.predict(norm.text)
        if prediction.spans:
            max_score = max(span.score for span in prediction.spans)
            if max_score >= self._inj_threshold:
                score = max(max_score, self._base_score * 0.5)
                return True, score, "span_model"
        doc_threshold = float(self._model.spec.config.get("doc_threshold", self._inj_threshold))
        if prediction.doc_score >= doc_threshold and prediction.doc_score_source == "doc_head":
            score = max(prediction.doc_score, self._base_score * 0.5)
            return True, score, "doc_head"
        return False, 0.0, ""


class CompositeEncodingClassifier:
    """Try span model on decoded text first; fall back to regex heuristic."""

    def __init__(self, *classifiers: EncodingClassifier) -> None:
        self._classifiers = classifiers

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]:
        for classifier in self._classifiers:
            malicious, score, subcategory = classifier.is_malicious(decoded)
            if malicious:
                return malicious, score, subcategory
        return False, 0.0, ""


def default_encoding_classifier(model: ModelProvider | None = None) -> EncodingClassifier:
    """Preferred backend: regex heuristic first, then span model on decoded blobs."""
    heuristic = HeuristicEncodingClassifier()
    if model is None:
        return heuristic
    return CompositeEncodingClassifier(
        heuristic,
        SpanModelEncodingClassifier(model),
    )


def iter_base64_blobs(text: str, *, max_blobs: int = 5) -> list[EncodingBlob]:
    blobs: list[EncodingBlob] = []
    for start, end, raw in _iter_base64_blob_spans(text):
        if len(blobs) >= max_blobs:
            break
        if not _is_probable_base64_blob(text, start, raw):
            continue
        decoded = _try_decode_base64_payload(raw)
        if decoded is None:
            continue
        blobs.append(
            EncodingBlob(
                start=start,
                end=end,
                raw=raw,
                decoded=decoded,
            )
        )
    return blobs


def iter_rot13_blobs(text: str, *, max_blobs: int = 5) -> list[EncodingBlob]:
    blobs: list[EncodingBlob] = []
    for match in ROT13_BLOB_PATTERN.finditer(text):
        if len(blobs) >= max_blobs:
            break
        raw = match.group(0)
        if not _is_probable_rot13_blob(raw):
            continue
        decoded = _rot13(raw)
        blobs.append(
            EncodingBlob(
                start=match.start(),
                end=match.end(),
                raw=raw,
                decoded=decoded,
            )
        )
    return blobs


def _append_encoding_findings(
    text: str,
    blobs: list[EncodingBlob],
    backend: EncodingClassifier,
    findings: list[Finding],
) -> None:
    for blob in blobs:
        if blob.decoded is None:
            continue

        malicious, score, subcategory = backend.is_malicious(blob.decoded)
        if malicious:
            findings.append(
                Finding(
                    category="injection",
                    subcategory="encoded_payload",
                    stage="encoding",
                    span_start=blob.start,
                    span_end=blob.end,
                    score=score,
                    evidence=f"Encoded payload matched: {subcategory}",
                    replacement="[BLOCKED:injection]",
                )
            )


def scan_encoding_blobs(
    text: str,
    classifier: EncodingClassifier | None = None,
) -> list[Finding]:
    """Stage 1a: extract → decode → classify → findings on original blob spans."""
    backend = classifier or HeuristicEncodingClassifier()
    findings: list[Finding] = []

    _append_encoding_findings(text, iter_base64_blobs(text), backend, findings)
    _append_encoding_findings(text, iter_rot13_blobs(text), backend, findings)

    return findings
