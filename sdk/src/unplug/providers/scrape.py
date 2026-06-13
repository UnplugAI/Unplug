"""UnplugScrape: Firecrawl-compatible entry that adds security filtering."""

from __future__ import annotations

from unplug.api.messages import ScrapeOutcome
from unplug.guards.scrape import ScrapeGuard
from unplug.providers.content.firecrawl import FirecrawlProvider


class UnplugScrape:
    """Use like Firecrawl, with built-in content filtering."""

    def __init__(self, api_key: str | None = None) -> None:
        if api_key:
            self._provider = FirecrawlProvider(api_key=api_key)
        else:
            self._provider = FirecrawlProvider.from_env()
        self._guard = ScrapeGuard(provider=self._provider)

    def scrape(self, url: str) -> ScrapeOutcome:
        return self._guard.scrape(url)
