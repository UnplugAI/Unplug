"""Incremental scan helpers for streamed LLM output and chunked documents."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from unplug.api.enums import Action, Source
from unplug.api.types import ScanRequest, ScanResult
from unplug.core.runtime.cache import (
    DEFAULT_PREFIX_OVERLAP_CHARS,
    effective_prefix_skip,
    merge_suffix_result,
)
from unplug.core.runtime.scan_merge import merge_scan_results

if TYPE_CHECKING:
    from unplug.guard import Guard

_DEFAULT_SCAN_EVERY = 1024
_DEFAULT_OVERLAP = DEFAULT_PREFIX_OVERLAP_CHARS


class StreamScanner:
    """Buffer streamed text and scan incrementally with overlap windows."""

    def __init__(
        self,
        guard: Guard,
        *,
        source: Source | str = Source.TOOL_OUTPUT,
        scan_every_chars: int = _DEFAULT_SCAN_EVERY,
        overlap_chars: int = _DEFAULT_OVERLAP,
        document_id: str | None = None,
    ) -> None:
        self._guard = guard
        self._source = Source(source) if isinstance(source, str) else source
        self._scan_every = max(64, scan_every_chars)
        # Never below the safe-prefix floor: overlap=0 skips the boundary and can miss
        # injections completed across chunk boundaries after a prior ALLOW.
        self._overlap = max(_DEFAULT_OVERLAP, overlap_chars)
        self._document_id = document_id
        self._buffer: list[str] = []
        self._buffer_len = 0
        self._last_result: ScanResult | None = None
        self._chars_since_scan = 0
        self._safe_prefix_len = 0

    @property
    def text(self) -> str:
        return "".join(self._buffer)

    @property
    def last_result(self) -> ScanResult | None:
        return self._last_result

    def push(self, chunk: str) -> ScanResult | None:
        """Append a streamed chunk; returns a scan result when the scan interval is reached."""
        if not chunk:
            return None
        self._buffer.append(chunk)
        self._buffer_len += len(chunk)
        self._chars_since_scan += len(chunk)
        if self._chars_since_scan < self._scan_every:
            return None
        self._chars_since_scan = 0
        return self._scan_accumulated()

    def flush(self) -> ScanResult:
        """Scan all buffered text (call when the stream ends)."""
        self._chars_since_scan = 0
        return self._scan_accumulated()

    def _scan_accumulated(self) -> ScanResult:
        body = self.text
        prefix_len = 0
        if (
            self._safe_prefix_len > 0
            and self._last_result is not None
            and self._last_result.action == Action.ALLOW
            and self._last_result.safe
        ):
            prefix_len = effective_prefix_skip(self._safe_prefix_len, self._overlap)

        scan_body = body[prefix_len:] if prefix_len else body
        request = self._guard._build_scan_request(scan_body, self._source)
        if self._document_id is not None:
            request = request.model_copy(update={"document_id": self._document_id})
        suffix_result = _scan_stream_request(self._guard, request, source=self._source)
        result = merge_suffix_result(suffix_result, prefix_len) if prefix_len else suffix_result

        if result.action == Action.ALLOW and result.safe:
            self._safe_prefix_len = len(body)
        else:
            self._safe_prefix_len = 0

        self._last_result = result
        return result


# Untrusted external text may carry registry secrets / canaries; dual-scan OutputPipeline.
_DUAL_SCAN_SOURCES = frozenset({Source.TOOL_OUTPUT, Source.RETRIEVED})


def _scan_stream_request(
    guard: Guard,
    request: ScanRequest,
    *,
    source: Source,
) -> ScanResult:
    """Input scan always; dual-scan OutputPipeline for untrusted external sources.

    Output runs on the input redacted base so secrets/canary sanitization composes
    with injection redaction instead of replacing it.
    """
    input_result = guard.scan_request(request, isolated=True)
    if source not in _DUAL_SCAN_SOURCES:
        return input_result
    base = (
        input_result.redacted_text
        if input_result.redacted_text is not None
        else request.text
    )
    output_request = request if base == request.text else request.model_copy(update={"text": base})
    output_result = guard.scan_output_request(output_request, isolated=True)
    return merge_scan_results(input_result, output_result)


def scan_stream(
    guard: Guard,
    chunks: Iterable[str],
    *,
    source: Source | str = Source.TOOL_OUTPUT,
    document_id: str | None = None,
) -> ScanResult:
    """Scan an iterable of text chunks as one document (full coverage via sliding windows).

    Defaults to ``TOOL_OUTPUT`` so streamed tool/LLM text gets registry/canary
    coverage. Pass ``source=USER`` for trusted user turns (skips output pipeline).
    """
    src = Source(source) if isinstance(source, str) else source
    request = guard._build_scan_request("".join(chunks), src)
    if document_id is not None:
        request = request.model_copy(update={"document_id": document_id})
    return _scan_stream_request(guard, request, source=src)
