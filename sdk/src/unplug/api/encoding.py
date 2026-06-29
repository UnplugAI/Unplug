"""Stable encoding-probe API for SDK dependents.

Import encoding classifiers from here instead of
``unplug.core.normalize.encodings``.
"""

from __future__ import annotations

from unplug.core.normalize.encodings import (
    BASE64_BLOB_PATTERN,
    INJECTION_PATTERNS,
    CompositeEncodingClassifier,
    EncodingBlob,
    EncodingClassifier,
    HeuristicEncodingClassifier,
    SpanModelEncodingClassifier,
    default_encoding_classifier,
    iter_base64_blobs,
    scan_encoding_blobs,
)

__all__ = [
    "BASE64_BLOB_PATTERN",
    "INJECTION_PATTERNS",
    "CompositeEncodingClassifier",
    "EncodingBlob",
    "EncodingClassifier",
    "HeuristicEncodingClassifier",
    "SpanModelEncodingClassifier",
    "default_encoding_classifier",
    "iter_base64_blobs",
    "scan_encoding_blobs",
]
