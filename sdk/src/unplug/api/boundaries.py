"""Stable untrusted-content boundary helpers.

Import boundary helpers from here instead of ``unplug.core.agent.boundaries``.
"""

from __future__ import annotations

from unplug.core.agent.boundaries import (
    SourceKind,
    WrappedContent,
    already_wrapped,
    generate_marker_id,
    is_untrusted_source,
    maybe_wrap_untrusted,
    sanitize_boundary_markers,
    strip_boundary_markers,
    wrap_external_content,
)

__all__ = [
    "SourceKind",
    "WrappedContent",
    "already_wrapped",
    "generate_marker_id",
    "is_untrusted_source",
    "maybe_wrap_untrusted",
    "sanitize_boundary_markers",
    "strip_boundary_markers",
    "wrap_external_content",
]
