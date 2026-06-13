"""Optional dependency: firecrawl scrape extra (lazy, logs install hint)."""

from __future__ import annotations

from typing import Any

from unplug.optional._base import require_attr

__all__ = ["get_firecrawl_app_class"]


def get_firecrawl_app_class() -> Any:
    return require_attr(
        "firecrawl",
        "FirecrawlApp",
        pip_extra="scrape",
        feature="Firecrawl scrape provider",
    )
