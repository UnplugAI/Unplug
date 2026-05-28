"""Tests for side-effect tool classification."""

from __future__ import annotations

from unplug.config.tools import ToolPolicyConfig


def test_side_effect_exec_and_shell() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_side_effect("exec")
    assert policy.is_side_effect("shell")
    assert policy.is_side_effect("run_terminal_cmd")


def test_side_effect_write_tools() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_side_effect("write_file")
    assert policy.is_side_effect("apply_patch")


def test_read_only_search() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_read_only("search")
    assert not policy.is_side_effect("search")


def test_taint_source_tools() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_taint_source("web_fetch")
    assert policy.is_taint_source("read_file")
    assert not policy.is_taint_source("exec")


def test_explicit_overrides() -> None:
    policy = ToolPolicyConfig(
        side_effect_tools=("custom_send",),
        taint_source_tools=("custom_fetch",),
    )
    assert policy.is_side_effect("custom_send")
    assert policy.is_taint_source("custom_fetch")


def test_profile_readonly_denies_side_effect() -> None:
    policy = ToolPolicyConfig(profile="readonly")
    assert not policy.is_permitted("shell")
    assert policy.is_permitted("search")
