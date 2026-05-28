"""Extract encoding blobs from original text (Base64 v1)."""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING, Protocol

from unplug.api.types import Finding
from unplug.core.normalize import Normalizer
from unplug.safeguards.injection.patterns import INJECTION_PATTERNS

if TYPE_CHECKING:
    from unplug.core.models import ModelProvider

# Same charset as normalize._decode_base64.
BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
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


def _is_plausible_decoded_payload(decoded: str) -> bool:
    """Skip decoded blobs that are not meaningful UTF-8 text (e.g. null-byte runs)."""
    if not decoded.strip():
        return False
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\t\r")
    return printable / len(decoded) >= 0.8


class EncodingBlob:
    """A contiguous encoding region in the original string."""

    __slots__ = ("start", "end", "raw", "decoded")

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
        if not prediction.spans:
            return False, 0.0, ""
        max_score = max(span.score for span in prediction.spans)
        if max_score < self._inj_threshold:
            return False, 0.0, ""
        score = max(max_score, self._base_score * 0.5)
        return True, score, "span_model"


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
    """Preferred backend: span model on decoded blobs when ML is available."""
    heuristic = HeuristicEncodingClassifier()
    if model is None:
        return heuristic
    return CompositeEncodingClassifier(
        SpanModelEncodingClassifier(model),
        heuristic,
    )


def iter_base64_blobs(text: str) -> list[EncodingBlob]:
    blobs: list[EncodingBlob] = []
    for match in BASE64_BLOB_PATTERN.finditer(text):
        raw = match.group(0)
        if not _is_probable_base64_blob(text, match.start(), raw):
            continue
        decoded: str | None = None
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except Exception:
            continue
        if not _is_plausible_decoded_payload(decoded):
            continue
        blobs.append(
            EncodingBlob(
                start=match.start(),
                end=match.end(),
                raw=raw,
                decoded=decoded,
            )
        )
    return blobs


def scan_encoding_blobs(
    text: str,
    classifier: EncodingClassifier | None = None,
) -> list[Finding]:
    """Stage 1a: extract → decode → classify → findings on original blob spans."""
    backend = classifier or HeuristicEncodingClassifier()
    findings: list[Finding] = []

    for blob in iter_base64_blobs(text):
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

    return findings
