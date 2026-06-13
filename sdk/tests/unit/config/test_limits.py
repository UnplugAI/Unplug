"""Tests for core/limits.py: input limits and tool permissions."""

from __future__ import annotations

from unplug.core.limits import LimitConfig, estimate_tokens


class TestLimitConfig:
    def test_defaults(self):
        lc = LimitConfig()
        assert lc.max_input_chars == 50_000
        assert lc.max_input_tokens is None
        assert lc.allowed_tools is None
        assert lc.blocked_tools == []

    def test_input_length_ok(self):
        lc = LimitConfig(max_input_chars=100)
        assert lc.check_input_length("short") is None

    def test_input_length_exceeded(self):
        lc = LimitConfig(max_input_chars=10)
        v = lc.check_input_length("this is too long for the limit")
        assert v is not None
        assert v.kind == "input_too_long"
        assert v.limit == 10
        assert v.actual == 30

    def test_tool_allowed_no_restrictions(self):
        lc = LimitConfig()
        assert lc.is_tool_allowed("any_tool") is True

    def test_tool_blocked(self):
        lc = LimitConfig(blocked_tools=["rm", "DROP"])
        assert lc.is_tool_allowed("rm") is False
        assert lc.is_tool_allowed("ls") is True

    def test_tool_allowlist(self):
        lc = LimitConfig(allowed_tools=["read_file", "search"])
        assert lc.is_tool_allowed("read_file") is True
        assert lc.is_tool_allowed("delete_file") is False

    def test_blocked_overrides_allowed(self):
        lc = LimitConfig(allowed_tools=["rm", "ls"], blocked_tools=["rm"])
        assert lc.is_tool_allowed("rm") is False
        assert lc.is_tool_allowed("ls") is True

    def test_frozen(self):
        lc = LimitConfig()
        try:
            lc.max_input_chars = 100
            assert False, "should be frozen"
        except Exception:
            pass


class TestTokenLimit:
    def test_estimate_empty(self):
        assert estimate_tokens("") == 0

    def test_estimate_word_text(self):
        # 5 words, 24 chars -> max(5, 6) = 6
        assert estimate_tokens("one two three four five!") == 6

    def test_estimate_unspaced_text(self):
        # No whitespace: words=1, falls back to chars/4
        blob = "a" * 400
        assert estimate_tokens(blob) == 100

    def test_token_limit_disabled_by_default(self):
        lc = LimitConfig()
        assert lc.check_input_length("word " * 10_000) is None

    def test_token_limit_ok(self):
        lc = LimitConfig(max_input_tokens=100)
        assert lc.check_input_length("hello world") is None

    def test_token_limit_exceeded(self):
        lc = LimitConfig(max_input_tokens=10)
        v = lc.check_input_length("word " * 50)
        assert v is not None
        assert v.kind == "input_tokens_exceeded"
        assert v.limit == 10
        assert v.actual > 10

    def test_token_limit_catches_unspaced_blob(self):
        lc = LimitConfig(max_input_tokens=50)
        v = lc.check_input_length("x" * 1000)
        assert v is not None
        assert v.kind == "input_tokens_exceeded"

    def test_char_limit_checked_before_tokens(self):
        lc = LimitConfig(max_input_chars=10, max_input_tokens=1)
        v = lc.check_input_length("this is way past both limits")
        assert v is not None
        assert v.kind == "input_too_long"
