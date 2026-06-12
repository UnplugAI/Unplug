"""Haystack integration — defend the RAG retrieval path.

Most prompt-injection defenses guard the user turn and miss the retrieval path:
a poisoned document in the store carries its payload straight into the prompt.
This component sits between the retriever and the prompt builder, scanning each
retrieved ``Document`` as untrusted RETRIEVED content, redacting or dropping on
findings, and boundary-wrapping survivors so injected instructions cannot
impersonate system text.

The scanning core (``scan_document``) is plain and has no Haystack dependency,
so it is fully testable without Haystack installed. The ``@component`` wrapper
lazy-imports Haystack and is only constructed when you actually use it.

Install the optional extra::

    pip install unplug-ai[haystack]

Usage::

    from haystack import Pipeline
    from unplug.integrations.haystack import UnplugDocumentGuard

    pipe = Pipeline()
    pipe.add_component("retriever", retriever)
    pipe.add_component("guard", UnplugDocumentGuard())
    pipe.add_component("prompt", prompt_builder)
    pipe.connect("retriever.documents", "guard.documents")
    pipe.connect("guard.documents", "prompt.documents")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.api.types import ScanResult
from unplug.core.taint import TrustLevel

if TYPE_CHECKING:
    from haystack import Document
else:
    # Populated by _build_component_class so Haystack's get_type_hints() can
    # resolve the string annotation list[Document] against module globals
    # (this file uses `from __future__ import annotations`).
    Document = None


class DocumentAction(StrEnum):
    """What the guard did to a single retrieved document."""

    KEPT = "kept"
    WRAPPED = "wrapped"
    REDACTED = "redacted"
    DROPPED = "dropped"


# Document metadata source hints that are less trusted than a plain vector hit.
_EXTERNAL_SOURCE_HINTS = ("web", "url", "http", "external", "internet", "crawl")


def trust_level_for_metadata(meta: dict[str, Any]) -> TrustLevel:
    """Map a Haystack document's metadata to an Unplug trust level.

    Documents fetched live from the web are EXTERNAL (least trusted); documents
    already scanned at ingestion can be marked TOOL_OUTPUT-equivalent by setting
    ``meta["unplug_ingest_scanned"] = True``. Everything else is RETRIEVED.
    """
    if meta.get("unplug_ingest_scanned") is True:
        return TrustLevel.RETRIEVED
    source = str(meta.get("source") or meta.get("origin") or "").lower()
    content_type = str(meta.get("content_type") or "").lower()
    is_external = any(hint in source for hint in _EXTERNAL_SOURCE_HINTS)
    if is_external or content_type.startswith("text/html"):
        return TrustLevel.EXTERNAL
    return TrustLevel.RETRIEVED


@dataclass
class DocumentScanOutcome:
    """Result of scanning one document's content."""

    content: str
    action: DocumentAction
    scan: ScanResult
    trust_level: TrustLevel = TrustLevel.RETRIEVED
    dropped: bool = False

    @property
    def risk_score(self) -> float:
        return self.scan.risk_score


@dataclass
class DocumentGuardReport:
    """Aggregate report across a batch of retrieved documents."""

    total: int = 0
    kept: int = 0
    wrapped: int = 0
    redacted: int = 0
    dropped: int = 0
    max_risk: float = 0.0
    flagged_indices: list[int] = field(default_factory=list)

    def record(self, index: int, outcome: DocumentScanOutcome) -> None:
        self.total += 1
        self.max_risk = max(self.max_risk, outcome.risk_score)
        if outcome.action in (DocumentAction.REDACTED, DocumentAction.DROPPED):
            self.flagged_indices.append(index)
        if outcome.action == DocumentAction.KEPT:
            self.kept += 1
        elif outcome.action == DocumentAction.WRAPPED:
            self.wrapped += 1
        elif outcome.action == DocumentAction.REDACTED:
            self.redacted += 1
        elif outcome.action == DocumentAction.DROPPED:
            self.dropped += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "kept": self.kept,
            "wrapped": self.wrapped,
            "redacted": self.redacted,
            "dropped": self.dropped,
            "max_risk": round(self.max_risk, 4),
            "flagged_indices": list(self.flagged_indices),
        }


def scan_document(
    guard: Guard,
    content: str,
    *,
    trust_level: TrustLevel = TrustLevel.RETRIEVED,
    drop_on_block: bool = True,
    wrap_safe: bool = True,
) -> DocumentScanOutcome:
    """Scan one document's text and decide keep / wrap / redact / drop.

    - BLOCK    -> drop (``drop_on_block``) else redact to the blocked placeholder.
    - REVIEW/REDACT with redacted_text -> redact (keep cleaned content).
    - otherwise -> boundary-wrap (``wrap_safe``) or keep as-is.

    No Haystack types cross this boundary, so it is unit-testable standalone.
    The retriever is always treated as untrusted RETRIEVED input; ``trust_level``
    is recorded for visibility (EXTERNAL hits stay flagged in the report).
    """
    result = guard.scan(content, source=Source.RETRIEVED)

    if result.action == Action.BLOCK:
        if drop_on_block:
            return DocumentScanOutcome(
                content="",
                action=DocumentAction.DROPPED,
                scan=result,
                trust_level=trust_level,
                dropped=True,
            )
        cleaned = result.redacted_text if result.redacted_text is not None else ""
        return DocumentScanOutcome(
            content=cleaned, action=DocumentAction.REDACTED, scan=result, trust_level=trust_level
        )

    if result.redacted_text is not None and result.redacted_text != content:
        return DocumentScanOutcome(
            content=result.redacted_text,
            action=DocumentAction.REDACTED,
            scan=result,
            trust_level=trust_level,
        )

    if wrap_safe:
        wrapped = guard.wrap_for_context(content, source=Source.RETRIEVED)
        return DocumentScanOutcome(
            content=wrapped, action=DocumentAction.WRAPPED, scan=result, trust_level=trust_level
        )

    return DocumentScanOutcome(
        content=content, action=DocumentAction.KEPT, scan=result, trust_level=trust_level
    )


@dataclass
class IngestionDecision:
    """Result of scanning a document at index time."""

    index_ok: bool
    scan: ScanResult
    meta_update: dict[str, Any]


def scan_for_ingestion(
    guard: Guard,
    content: str,
    *,
    block_on_injection: bool = True,
) -> IngestionDecision:
    """Scan a document before it enters the store (defense at ingestion).

    Returns ``index_ok=False`` when the document should be rejected from the
    store. On accept, ``meta_update`` carries ``unplug_ingest_scanned=True`` plus
    the recorded risk so retrieval-time scanning can trust the prior pass.
    """
    result = guard.scan(content, source=Source.RETRIEVED)
    blocked = block_on_injection and result.action == Action.BLOCK
    index_ok = not blocked
    meta_update: dict[str, Any] = {
        "unplug_ingest_risk": round(result.risk_score, 4),
        "unplug_ingest_blocked": blocked,
    }
    if index_ok:
        meta_update["unplug_ingest_scanned"] = True
    return IngestionDecision(index_ok=index_ok, scan=result, meta_update=meta_update)


def _require_haystack() -> Any:
    try:
        import haystack
    except ImportError as exc:  # pragma: no cover - exercised only without extra
        msg = "Haystack integration requires the extra: pip install unplug-ai[haystack]"
        raise ImportError(msg) from exc
    return haystack


def _build_component_class() -> type:
    global Document
    haystack = _require_haystack()
    component = haystack.component
    Document = haystack.Document

    @component
    class UnplugDocumentGuard:
        """Haystack component: scan + clean retrieved documents before the prompt.

        Inputs:  ``documents: list[Document]``
        Outputs: ``documents: list[Document]`` (cleaned), ``report: dict``
        """

        def __init__(
            self,
            guard: Guard | None = None,
            *,
            drop_on_block: bool = True,
            wrap_safe: bool = True,
        ) -> None:
            self._guard = guard or Guard()
            self._drop_on_block = drop_on_block
            self._wrap_safe = wrap_safe

        @component.output_types(documents=list, report=dict)
        def run(self, documents: list[Document]) -> dict[str, Any]:
            cleaned: list[Document] = []
            report = DocumentGuardReport()
            for index, doc in enumerate(documents):
                meta = dict(doc.meta or {})
                trust = trust_level_for_metadata(meta)
                outcome = scan_document(
                    self._guard,
                    doc.content or "",
                    trust_level=trust,
                    drop_on_block=self._drop_on_block,
                    wrap_safe=self._wrap_safe,
                )
                report.record(index, outcome)
                if outcome.dropped:
                    continue
                meta["unplug_action"] = outcome.action.value
                meta["unplug_risk"] = round(outcome.risk_score, 4)
                cleaned.append(Document(content=outcome.content, meta=meta))
            self._guard.notify_taint_source("haystack_retriever")
            return {"documents": cleaned, "report": report.to_dict()}

    return UnplugDocumentGuard


_UnplugDocumentGuard: type | None = None


def __getattr__(name: str) -> Any:
    # Lazily build the @component class on first access so importing this module
    # (e.g. for scan_document in tests) never requires Haystack to be installed.
    global _UnplugDocumentGuard
    if name == "UnplugDocumentGuard":
        if _UnplugDocumentGuard is None:
            _UnplugDocumentGuard = _build_component_class()
        return _UnplugDocumentGuard
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
