"""Tests for core/content.py: content provider protocol and models."""

from __future__ import annotations

from unplug.core.content import CleanResult, ContentProvider, ScrapedContent


class TestScrapedContent:
    def test_creation(self):
        sc = ScrapedContent(url="https://example.com", markdown="# Hello")
        assert sc.url == "https://example.com"
        assert sc.markdown == "# Hello"
        assert sc.word_count == 0
        assert sc.metadata == {}

    def test_with_metadata(self):
        sc = ScrapedContent(
            url="https://example.com",
            markdown="content",
            title="Test Page",
            description="A test",
            word_count=150,
            scrape_ms=42.5,
            metadata={"author": "test"},
        )
        assert sc.title == "Test Page"
        assert sc.scrape_ms == 42.5


class TestCleanResult:
    def test_creation(self):
        cr = CleanResult(text="clean text", original_length=500, cleaned_length=50)
        assert cr.elements_removed == 0

    def test_compression_ratio(self):
        cr = CleanResult(text="x", original_length=1000, cleaned_length=100)
        assert cr.original_length / cr.cleaned_length == 10.0


class TestContentProviderProtocol:
    def test_protocol_check(self):
        class MockProvider:
            async def scrape(self, url: str) -> ScrapedContent:
                return ScrapedContent(url=url, markdown="")

            async def clean(self, html: str) -> CleanResult:
                return CleanResult(text="")

        assert isinstance(MockProvider(), ContentProvider)

    def test_non_provider_rejected(self):
        class NotAProvider:
            pass

        assert not isinstance(NotAProvider(), ContentProvider)
