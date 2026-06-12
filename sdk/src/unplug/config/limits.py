"""Token and input limits — guards against unbounded consumption (OWASP LLM10)."""

from __future__ import annotations

from pydantic import BaseModel, Field


def estimate_tokens(text: str) -> int:
    """Offline token estimate: max of whitespace words and chars/4.

    Whitespace splitting undercounts text without spaces (CJK, base64 blobs),
    chars/4 undercounts whitespace-dense text; the max of both is a
    conservative bound without pulling in a tokenizer dependency.
    """
    if not text:
        return 0
    return max(len(text.split()), len(text) // 4)


class LimitConfig(BaseModel):
    """Configurable limits for input size and tool call frequency."""

    model_config = {"frozen": True}

    max_input_chars: int = 50_000
    max_input_tokens: int | None = None
    max_tool_calls_per_session: int = 100
    allowed_tools: list[str] | None = None
    blocked_tools: list[str] = Field(default_factory=list)

    def is_tool_allowed(self, tool_name: str) -> bool:
        if tool_name in self.blocked_tools:
            return False
        if self.allowed_tools is not None:
            return tool_name in self.allowed_tools
        return True

    def check_input_length(self, text: str) -> LimitViolation | None:
        if len(text) > self.max_input_chars:
            return LimitViolation(
                kind="input_too_long",
                limit=self.max_input_chars,
                actual=len(text),
                message=f"Input exceeds {self.max_input_chars} chars ({len(text)} provided)",
            )
        if self.max_input_tokens is not None:
            tokens = estimate_tokens(text)
            if tokens > self.max_input_tokens:
                return LimitViolation(
                    kind="input_tokens_exceeded",
                    limit=self.max_input_tokens,
                    actual=tokens,
                    message=(f"Input exceeds {self.max_input_tokens} tokens (~{tokens} estimated)"),
                )
        return None

    def check_tool_call_count(self, count: int) -> LimitViolation | None:
        if count > self.max_tool_calls_per_session:
            return LimitViolation(
                kind="tool_calls_exceeded",
                limit=self.max_tool_calls_per_session,
                actual=count,
                message=(
                    f"Tool calls exceed session limit ({count} > {self.max_tool_calls_per_session})"
                ),
            )
        return None


class LimitViolation(BaseModel):
    """Describes a limit that was exceeded."""

    kind: str
    limit: int
    actual: int
    message: str
