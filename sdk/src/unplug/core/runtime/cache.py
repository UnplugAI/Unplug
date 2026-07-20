"""Safe-prefix and chunk caches for incremental scanning."""

from __future__ import annotations

import hashlib
from collections import OrderedDict

from pydantic import BaseModel, Field

from unplug.api.enums import Action
from unplug.api.types import Finding, ScanResult
from unplug.core.runtime.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION

# Match StreamScanner default so append-only scans re-check the boundary.
DEFAULT_PREFIX_OVERLAP_CHARS = 256


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SafePrefixState(BaseModel):
    """Verified-clean prefix; invalidated if text prefix changes."""

    prefix_len: int = Field(ge=0)
    prefix_hash: str = ""

    def verify(self, text: str) -> bool:
        if self.prefix_len <= 0:
            return False
        if self.prefix_len > len(text):
            return False
        return _sha256(text[: self.prefix_len]) == self.prefix_hash

    @classmethod
    def from_text(cls, text: str, prefix_len: int) -> SafePrefixState:
        return cls(prefix_len=prefix_len, prefix_hash=_sha256(text[:prefix_len]))


class CacheKeyParts(BaseModel):
    doc_key: str
    full_hash: str
    normalizer_version: str
    model_version: str
    source: str = ""
    policy_fingerprint: str = ""


def cache_key_parts(
    text: str,
    *,
    document_id: str | None,
    normalizer_version: str = NORMALIZER_VERSION,
    model_version: str = MODEL_VERSION_LOCAL,
    source: str = "",
    policy_fingerprint: str = "",
) -> CacheKeyParts:
    doc_key = f"doc:{document_id}" if document_id else f"hash:{_sha256(text)[:16]}"
    return CacheKeyParts(
        doc_key=doc_key,
        full_hash=_sha256(text),
        normalizer_version=normalizer_version,
        model_version=model_version,
        source=source,
        policy_fingerprint=policy_fingerprint,
    )


def prefix_storage_key(parts: CacheKeyParts) -> str:
    return (
        f"{parts.doc_key}|{parts.source}|{parts.policy_fingerprint}|"
        f"{parts.normalizer_version}|{parts.model_version}"
    )


def chunk_storage_key(parts: CacheKeyParts) -> str:
    return (
        f"{parts.full_hash}|{parts.source}|{parts.policy_fingerprint}|"
        f"{parts.normalizer_version}|{parts.model_version}"
    )


def effective_prefix_skip(prefix_len: int, overlap_chars: int) -> int:
    """Return the scan start offset, re-scanning ``overlap_chars`` at the boundary."""
    if prefix_len <= 0:
        return 0
    overlap = max(0, overlap_chars)
    return max(0, prefix_len - overlap)


class ScanCache:
    """In-process LRU: safe prefix per document + chunk results by content hash."""

    def __init__(self, *, max_chunk_entries: int = 256) -> None:
        self._max_chunk_entries = max_chunk_entries
        self._prefixes: dict[str, SafePrefixState] = {}
        self._chunks: OrderedDict[str, ScanResult] = OrderedDict()

    def cache_key_parts(
        self,
        text: str,
        *,
        document_id: str | None,
        normalizer_version: str = NORMALIZER_VERSION,
        model_version: str = MODEL_VERSION_LOCAL,
        source: str = "",
        policy_fingerprint: str = "",
    ) -> CacheKeyParts:
        return cache_key_parts(
            text,
            document_id=document_id,
            normalizer_version=normalizer_version,
            model_version=model_version,
            source=source,
            policy_fingerprint=policy_fingerprint,
        )

    def prefix_storage_key(self, parts: CacheKeyParts) -> str:
        return prefix_storage_key(parts)

    def chunk_storage_key(self, parts: CacheKeyParts) -> str:
        return chunk_storage_key(parts)

    def get_safe_prefix(self, parts: CacheKeyParts) -> SafePrefixState | None:
        return self._prefixes.get(prefix_storage_key(parts))

    def set_safe_prefix(self, parts: CacheKeyParts, state: SafePrefixState) -> None:
        self._prefixes[prefix_storage_key(parts)] = state

    def get_chunk(self, content_hash: str) -> ScanResult | None:
        return self._chunks.get(content_hash)

    def set_chunk(self, content_hash: str, result: ScanResult) -> None:
        self._chunks[content_hash] = result
        self._chunks.move_to_end(content_hash)
        while len(self._chunks) > self._max_chunk_entries:
            self._chunks.popitem(last=False)

    def get_chunk_for_parts(self, parts: CacheKeyParts) -> ScanResult | None:
        return self.get_chunk(chunk_storage_key(parts))

    def set_chunk_for_parts(self, parts: CacheKeyParts, result: ScanResult) -> None:
        self.set_chunk(chunk_storage_key(parts), result)

    @staticmethod
    def should_advance_prefix(action: Action, *, advance_on_redact: bool) -> bool:
        if action == Action.BLOCK:
            return False
        if action == Action.REDACT:
            return advance_on_redact
        return action in (Action.ALLOW, Action.REVIEW)


def offset_findings(findings: list[Finding], offset: int) -> list[Finding]:
    if offset <= 0:
        return findings
    shifted: list[Finding] = []
    for f in findings:
        shifted.append(
            Finding(
                category=f.category,
                subcategory=f.subcategory,
                stage=f.stage,
                span_start=f.span_start + offset,
                span_end=f.span_end + offset,
                score=f.score,
                evidence=f.evidence,
                replacement=f.replacement,
            )
        )
    return shifted


def merge_suffix_result(suffix: ScanResult, prefix_len: int) -> ScanResult:
    """Combine suffix scan with an already-verified prefix region."""
    findings = offset_findings(suffix.findings, prefix_len)
    risk_score = max((f.score for f in findings), default=0.0)
    redacted: str | None = None
    if suffix.redacted_text is not None and prefix_len > 0:
        # Caller must merge redacted bodies externally if needed; preserve suffix slice.
        redacted = suffix.redacted_text
    return ScanResult(
        safe=suffix.safe,
        action=suffix.action,
        risk_score=risk_score,
        findings=findings,
        redacted_text=redacted,
        latency_ms=suffix.latency_ms,
        stages_run=[*suffix.stages_run, "safe_prefix"],
    )
