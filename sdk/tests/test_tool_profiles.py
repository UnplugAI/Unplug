"""Tests for tool access profiles."""

from __future__ import annotations

from unplug import Guard
from unplug.api.enums import Action
from unplug.config.guard import GuardConfig
from unplug.config.tools import ToolPolicyConfig, ToolProfile, resolve_profile


def test_resolve_profile_names() -> None:
    assert resolve_profile("readonly") is ToolProfile.READONLY
    assert resolve_profile("full") is ToolProfile.FULL


def test_readonly_profile_blocks_shell_allows_search() -> None:
    cfg = GuardConfig(tools=ToolPolicyConfig(profile="readonly"))
    guard = Guard(config=cfg)
    assert guard.check_tool_call("shell", {"command": "ls"}).action == Action.BLOCK
    assert guard.check_tool_call("search", {"query": "weather"}).action == Action.ALLOW


def test_messaging_profile_blocks_shell_allows_send() -> None:
    cfg = GuardConfig(tools=ToolPolicyConfig(profile="messaging"))
    guard = Guard(config=cfg)
    assert guard.check_tool_call("shell", {"command": "ls"}).action == Action.BLOCK
    assert guard.check_tool_call("send_message", {"body": "hi"}).action == Action.ALLOW


def test_full_profile_no_extra_blocks() -> None:
    cfg = GuardConfig(tools=ToolPolicyConfig(profile="full"))
    guard = Guard(config=cfg)
    assert guard.check_tool_call("lookup_docs", {"q": "x"}).action == Action.ALLOW
