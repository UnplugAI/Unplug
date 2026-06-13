"""Tests for core/taint.py: TaintedText, TrustLevel, Tagger."""

from unplug.core.taint import Tagger, TaintedText, TrustLevel, trust_level_from_source
from unplug.models import Source


class TestTrustLevel:
    def test_values(self):
        assert TrustLevel.TRUSTED == "trusted"
        assert TrustLevel.USER == "user"
        assert TrustLevel.RETRIEVED == "retrieved"
        assert TrustLevel.TOOL_OUTPUT == "tool_output"
        assert TrustLevel.EXTERNAL == "external"
        assert TrustLevel.UNKNOWN == "unknown"

    def test_str_enum(self):
        assert isinstance(TrustLevel.USER, str)


class TestTrustLevelFromSource:
    def test_system_maps_to_trusted(self):
        assert trust_level_from_source(Source.SYSTEM) == TrustLevel.TRUSTED

    def test_user_maps_to_user(self):
        assert trust_level_from_source(Source.USER) == TrustLevel.USER

    def test_retrieved_maps_to_retrieved(self):
        assert trust_level_from_source(Source.RETRIEVED) == TrustLevel.RETRIEVED

    def test_tool_output_maps_to_tool_output(self):
        assert trust_level_from_source(Source.TOOL_OUTPUT) == TrustLevel.TOOL_OUTPUT


class TestTaintedText:
    def test_creation(self):
        tt = TaintedText(text="hello", trust_level=TrustLevel.USER, origin="test")
        assert tt.text == "hello"
        assert tt.trust_level == TrustLevel.USER
        assert tt.origin == "test"
        assert tt.parent_id is None
        assert tt.metadata == {}
        assert tt.id is not None
        assert tt.timestamp > 0

    def test_unique_ids(self):
        a = TaintedText(text="a", trust_level=TrustLevel.USER, origin="test")
        b = TaintedText(text="b", trust_level=TrustLevel.USER, origin="test")
        assert a.id != b.id

    def test_metadata(self):
        tt = TaintedText(
            text="hello",
            trust_level=TrustLevel.EXTERNAL,
            origin="web",
            metadata={"url": "https://example.com"},
        )
        assert tt.metadata["url"] == "https://example.com"

    def test_parent_id(self):
        parent = TaintedText(text="parent", trust_level=TrustLevel.USER, origin="test")
        child = TaintedText(
            text="child",
            trust_level=TrustLevel.RETRIEVED,
            origin="search",
            parent_id=parent.id,
        )
        assert child.parent_id == parent.id


class TestTagger:
    def setup_method(self):
        self.tagger = Tagger()

    def test_tag(self):
        tt = self.tagger.tag("hello", TrustLevel.USER, "user_input")
        assert tt.text == "hello"
        assert tt.trust_level == TrustLevel.USER
        assert tt.origin == "user_input"

    def test_tag_with_metadata(self):
        tt = self.tagger.tag("hello", TrustLevel.EXTERNAL, "web", source_url="https://example.com")
        assert tt.metadata["source_url"] == "https://example.com"

    def test_tag_with_parent(self):
        tt = self.tagger.tag("hello", TrustLevel.USER, "test", parent_id="parent-123")
        assert tt.parent_id == "parent-123"

    def test_tag_from_source(self):
        tt = self.tagger.tag_from_source("hello", Source.USER, "user_message")
        assert tt.trust_level == TrustLevel.USER
        assert tt.origin == "user_message"

    def test_tag_from_source_system(self):
        tt = self.tagger.tag_from_source("system prompt", Source.SYSTEM, "system")
        assert tt.trust_level == TrustLevel.TRUSTED

    def test_derive(self):
        parent = self.tagger.tag("original", TrustLevel.EXTERNAL, "web")
        child = self.tagger.derive(parent, "derived text")
        assert child.text == "derived text"
        assert child.trust_level == TrustLevel.EXTERNAL
        assert child.origin == "web"
        assert child.parent_id == parent.id
        assert child.id != parent.id

    def test_derive_inherits_metadata(self):
        parent = self.tagger.tag("original", TrustLevel.USER, "test", key="value")
        child = self.tagger.derive(parent, "derived")
        assert child.metadata["key"] == "value"

    def test_derive_override_metadata(self):
        parent = self.tagger.tag("original", TrustLevel.USER, "test", key="old")
        child = self.tagger.derive(parent, "derived", key="new", extra="data")
        assert child.metadata["key"] == "new"
        assert child.metadata["extra"] == "data"
