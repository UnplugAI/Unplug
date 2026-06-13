"""Scrape guard: Firecrawl fetch plus security filter."""

from __future__ import annotations

from unplug.api.messages import ScrapeOutcome
from unplug.config.messages import MessageConfig
from unplug.guard import Guard
from unplug.guards.base import BaseGuardFacade
from unplug.orchestrators.scrape import ScrapeOrchestrator
from unplug.providers.content.firecrawl import FirecrawlProvider
from unplug.providers.content.protocol import ContentProvider


class ScrapeGuard(BaseGuardFacade):
    """Drop-in: scrape a URL and return agent-safe markdown."""

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        api_key: str | None = None,
        provider: ContentProvider | None = None,
        messages: MessageConfig | None = None,
    ) -> None:
        super().__init__(guard=guard, messages=messages)
        resolved = provider or (FirecrawlProvider(api_key=api_key) if api_key else None)
        self._orchestrator = ScrapeOrchestrator(
            self._guard,
            provider=resolved,
            messages=self._messages,
        )

    def scrape(self, url: str) -> ScrapeOutcome:
        """Fetch URL and filter content for the agent (sync-safe)."""
        return self._orchestrator.run(url)

    async def scrape_async(self, url: str) -> ScrapeOutcome:
        """Fetch URL and filter content: use inside async agents."""
        return await self._orchestrator.run_async(url)


def scrape(url: str, *, guard: Guard | None = None, api_key: str | None = None) -> ScrapeOutcome:
    """One-liner: scrape and filter a URL."""
    return ScrapeGuard(guard=guard, api_key=api_key).scrape(url)
