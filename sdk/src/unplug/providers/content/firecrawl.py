"""Firecrawl-backed scraper (optional unplug-ai[scrape] extra)."""

from __future__ import annotations

import time
from typing import Any

from unplug.optional.scrape import get_firecrawl_app_class
from unplug.providers.content.env import load_firecrawl_api_key
from unplug.providers.content.protocol import CleanResult, ScrapedContent


def _document_to_scraped(url: str, doc: Any, scrape_ms: float) -> ScrapedContent:
    markdown = getattr(doc, "markdown", None) or ""
    metadata = getattr(doc, "metadata", None)
    title = getattr(metadata, "title", None) if metadata else None
    description = getattr(metadata, "description", None) if metadata else None
    return ScrapedContent(
        url=url,
        markdown=markdown,
        title=title,
        description=description,
        word_count=len(markdown.split()) if markdown else 0,
        scrape_ms=scrape_ms,
    )


class FirecrawlProvider:
    """Local Firecrawl client. Uses FIRECRAWL_API_KEY from env or .env."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or load_firecrawl_api_key()
        self._client: Any | None = None

    @classmethod
    def from_env(cls) -> FirecrawlProvider:
        return cls()

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        firecrawl_app = get_firecrawl_app_class()
        self._client = firecrawl_app(api_key=self._api_key)
        return self._client

    def scrape_sync(self, url: str) -> ScrapedContent:
        start = time.perf_counter()
        client = self._ensure_client()
        doc = client.scrape(url)
        elapsed = (time.perf_counter() - start) * 1000
        return _document_to_scraped(url, doc, elapsed)

    async def scrape(self, url: str) -> ScrapedContent:
        import asyncio

        return await asyncio.to_thread(self.scrape_sync, url)

    async def clean(self, html: str) -> CleanResult:
        return CleanResult(text=html, original_length=len(html), cleaned_length=len(html))
