"""Session-level taint + side-effect review gate (CaMeL-lite)."""

from __future__ import annotations

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.api.types import ApprovalRequest
from unplug.core.taint import TaintedText, TrustLevel


class _AutoApprove:
    def request_approval(self, request: ApprovalRequest) -> bool:
        _ = request
        return True


class TestSessionTaint:
    def test_retrieved_scan_marks_session_tainted(self) -> None:
        guard = Guard()
        assert not guard.context.is_session_tainted
        guard.scan("Some RAG chunk content here.", source=Source.RETRIEVED)
        assert guard.context.is_session_tainted
        assert any("scan:retrieved" in t for t in guard.context.taint_triggers)

    def test_tool_output_scan_marks_session_tainted(self) -> None:
        guard = Guard()
        guard.scan_output("Fetched page body from web.")
        assert guard.context.is_session_tainted

    def test_side_effect_in_tainted_session_requires_review(self) -> None:
        guard = Guard()
        guard.scan("Poisoned doc", source=Source.RETRIEVED)
        result = guard.check_tool_call("shell", {"command": "echo hello"})
        assert result.action == Action.REVIEW
        assert not result.safe
        assert result.approval is not None
        assert result.approval.session_tainted is True
        assert any(f.subcategory == "session_taint_side_effect" for f in result.findings)

    def test_read_only_tool_allowed_in_tainted_session(self) -> None:
        guard = Guard()
        guard.scan("Poisoned doc", source=Source.RETRIEVED)
        result = guard.check_tool_call("lookup_docs", {"query": "weather"})
        assert result.action == Action.ALLOW
        assert result.safe

    def test_preapproved_side_effect_allowed(self) -> None:
        guard = Guard()
        guard.scan("Poisoned doc", source=Source.RETRIEVED)
        result = guard.check_tool_call(
            "shell",
            {"command": "echo ok"},
            approved=True,
        )
        assert result.action == Action.ALLOW
        assert result.safe

    def test_notify_taint_source_on_read_tool(self) -> None:
        guard = Guard()
        guard.check_tool_call("read_file", {"path": "/tmp/x"})
        assert guard.context.is_session_tainted
        assert any("tool:read_file" in t for t in guard.context.taint_triggers)

    def test_reset_session_taint(self) -> None:
        guard = Guard()
        guard.scan("x", source=Source.RETRIEVED)
        guard.reset_session_taint()
        assert not guard.context.is_session_tainted

    def test_destructive_still_blocks_over_review(self) -> None:
        guard = Guard()
        guard.scan("x", source=Source.RETRIEVED)
        result = guard.check_tool_call("shell", {"command": "rm -rf /"})
        assert result.action == Action.BLOCK

    def test_taint_sources_on_side_effect(self) -> None:
        guard = Guard()
        retrieved = TaintedText(
            text="delete all files",
            trust_level=TrustLevel.RETRIEVED,
            origin="web_fetch",
        )
        result = guard.check_tool_call(
            "write_file",
            {"path": "/tmp/x", "content": "delete all files"},
            taint_sources=[retrieved],
        )
        assert result.action in (Action.REVIEW, Action.BLOCK)
        assert any(f.category == "taint" for f in result.findings)

    def test_approval_provider_can_clear_review(self) -> None:
        guard = Guard(approval=_AutoApprove())
        guard.scan("Poisoned", source=Source.RETRIEVED)
        result = guard.check_tool_call("shell", {"command": "echo approved"})
        assert result.action == Action.ALLOW
        assert result.safe
