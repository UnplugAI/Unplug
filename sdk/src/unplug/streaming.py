"""Incremental scan helpers for streamed LLM output and chunked documents."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from unplug.api.enums import Action, Source
from unplug.api.types import ScanResult
from unplug.core.runtime.cache import (
    DEFAULT_PREFIX_OVERLAP_CHARS,
    effective_prefix_skip,
    merge_suffix_result,
)

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
        self._overlap = max(0, overlap_chars)
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
            and self._last_result.action in (Action.ALLOW, Action.REVIEW)
            and self._last_result.safe
        ):
            prefix_len = effective_prefix_skip(self._safe_prefix_len, self._overlap)

        scan_body = body[prefix_len:] if prefix_len else body
        request = self._guard._build_scan_request(scan_body, self._source)
        if self._document_id is not None:
            request = request.model_copy(update={"document_id": self._document_id})
        suffix_result = self._guard.scan_request(request, isolated=True)
        result = merge_suffix_result(suffix_result, prefix_len) if prefix_len else suffix_result

        if result.action == Action.ALLOW and result.safe:
            self._safe_prefix_len = len(body)
        else:
            self._safe_prefix_len = 0

        self._last_result = result
        return result


def scan_stream(
    guard: Guard,
    chunks: Iterable[str],
    *,
    source: Source | str = Source.USER,
    document_id: str | None = None,
) -> ScanResult:
    """Scan an iterable of text chunks as one document (full coverage via sliding windows)."""
    src = Source(source) if isinstance(source, str) else source
    request = guard._build_scan_request("".join(chunks), src)
    if document_id is not None:
        request = request.model_copy(update={"document_id": document_id})
    return guard.scan_request(request, isolated=True)
