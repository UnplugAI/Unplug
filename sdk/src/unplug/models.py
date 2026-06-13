"""Shared schemas: re-exported from unplug.api for backward compatibility."""

from __future__ import annotations

from unplug.api.enums import Action, Source
from unplug.api.types import (
    ApprovalRequest,
    BatchScanRequest,
    Finding,
    HealthResponse,
    ScanRequest,
    ScanResult,
)
from unplug.config.policy import ScanPolicy

__all__ = [
    "Action",
    "ApprovalRequest",
    "BatchScanRequest",
    "Finding",
    "HealthResponse",
    "ScanPolicy",
    "ScanRequest",
    "ScanResult",
    "Source",
]
