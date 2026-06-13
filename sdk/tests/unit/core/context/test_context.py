"""Tests for core/context.py: ExecutionContext, ToolCall."""

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.taint import TaintedText, TrustLevel


def _make_text(text: str = "hello", trust: TrustLevel = TrustLevel.USER) -> TaintedText:
    return TaintedText(text=text, trust_level=trust, origin="test")


class TestToolCall:
    def test_creation(self):
        tc = ToolCall(tool_name="search", arguments={"query": "test"})
        assert tc.tool_name == "search"
        assert tc.arguments == {"query": "test"}
        assert tc.taint_sources == []
        assert tc.result is None
        assert tc.approved is None
        assert tc.timestamp > 0

    def test_with_taint_sources(self):
        source = _make_text("untrusted", TrustLevel.EXTERNAL)
        tc = ToolCall(tool_name="delete", arguments={"id": 1}, taint_sources=[source])
        assert len(tc.taint_sources) == 1
        assert tc.taint_sources[0].trust_level == TrustLevel.EXTERNAL


class TestExecutionContext:
    def test_defaults(self):
        ctx = ExecutionContext()
        assert ctx.session_id is not None
        assert ctx.user_intent is None
        assert ctx.conversation == []
        assert ctx.tool_calls == []
        assert ctx.risk_trajectory == []
        assert ctx.secrets_registry is None

    def test_custom_session_id(self):
        ctx = ExecutionContext(session_id="my-session")
        assert ctx.session_id == "my-session"

    def test_with_user_intent(self):
        intent = _make_text("summarize this document")
        ctx = ExecutionContext(user_intent=intent)
        assert ctx.user_intent is not None
        assert ctx.user_intent.text == "summarize this document"

    def test_add_message(self):
        ctx = ExecutionContext()
        msg = _make_text("hello")
        ctx.add_message(msg)
        assert len(ctx.conversation) == 1
        assert ctx.conversation[0].text == "hello"

    def test_add_multiple_messages(self):
        ctx = ExecutionContext()
        ctx.add_message(_make_text("first"))
        ctx.add_message(_make_text("second"))
        assert len(ctx.conversation) == 2

    def test_add_tool_call(self):
        ctx = ExecutionContext()
        tc = ToolCall(tool_name="search", arguments={"q": "test"})
        ctx.add_tool_call(tc)
        assert len(ctx.tool_calls) == 1
        assert ctx.tool_calls[0].tool_name == "search"

    def test_update_risk(self):
        ctx = ExecutionContext()
        ctx.update_risk(0.1)
        ctx.update_risk(0.3)
        assert ctx.risk_trajectory == [0.1, 0.3]

    def test_risk_trend_insufficient_data(self):
        ctx = ExecutionContext()
        assert ctx.get_risk_trend() == 0.0
        ctx.update_risk(0.5)
        assert ctx.get_risk_trend() == 0.0

    def test_risk_trend_flat(self):
        ctx = ExecutionContext()
        for _ in range(5):
            ctx.update_risk(0.5)
        assert ctx.get_risk_trend() == 0.0

    def test_risk_trend_escalating(self):
        ctx = ExecutionContext()
        for v in [0.1, 0.2, 0.3, 0.4, 0.5]:
            ctx.update_risk(v)
        trend = ctx.get_risk_trend()
        assert trend > 0

    def test_risk_trend_deescalating(self):
        ctx = ExecutionContext()
        for v in [0.5, 0.4, 0.3, 0.2, 0.1]:
            ctx.update_risk(v)
        trend = ctx.get_risk_trend()
        assert trend < 0

    def test_risk_trend_window(self):
        ctx = ExecutionContext()
        for v in [0.1, 0.9, 0.5, 0.5, 0.5, 0.5, 0.5]:
            ctx.update_risk(v)
        trend = ctx.get_risk_trend(window=3)
        assert trend == 0.0
