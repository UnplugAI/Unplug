"""Tests for optional LiteLLM judge extra."""

from __future__ import annotations

import pytest

from unplug.core.extras import missing_extra_message


def test_litellm_missing_message() -> None:
    msg = missing_extra_message(pip_extra="litellm", feature="LiteLLM judge")
    assert "unplug-ai[litellm]" in msg


def test_create_litellm_judge_without_extra() -> None:
    pytest.importorskip("sys")
    from unplug.judge.litellm_judge import create_litellm_judge

    try:
        import litellm  # noqa: F401
    except ImportError:
        with pytest.raises(ImportError, match="unplug-ai\\[litellm\\]"):
            create_litellm_judge("gpt-4o")
    else:
        judge = create_litellm_judge("gpt-4o")
        assert judge is not None
