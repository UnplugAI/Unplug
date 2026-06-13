"""Optional dependency helpers: re-export from unplug.optional._base."""

from __future__ import annotations

from unplug.optional._base import missing_extra_message, raise_missing_extra, require_extra

__all__ = ["missing_extra_message", "raise_missing_extra", "require_extra"]
