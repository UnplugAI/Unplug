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


def test_camel_case_names_classify() -> None:
    """Claude Code names its tools WebFetch and NotebookEdit, not web_fetch (#166)."""
    policy = ToolPolicyConfig()
    assert policy.is_taint_source("WebFetch")
    assert policy.is_taint_source("WebSearch")
    assert policy.is_side_effect("NotebookEdit")
    assert policy.is_side_effect("sendEmail")


def test_mcp_prefixed_names_classify() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_side_effect("mcp__slack__send_message")
    assert policy.is_side_effect("mcp__gmail__send_email")
    assert policy.is_side_effect("mcp__shell__bash")


def test_vendor_prefixed_verbs_classify() -> None:
    """The verb decides, wherever the vendor put it."""
    policy = ToolPolicyConfig()
    assert policy.is_side_effect("slack_post_message")
    assert policy.is_side_effect("github_create_issue")
    assert policy.is_side_effect("gmail_send")
    assert policy.is_side_effect("post_tweet")


def test_ordinary_getters_are_not_side_effects() -> None:
    """The broadened patterns must not swallow plain reads."""
    policy = ToolPolicyConfig()
    for name in ("get_weather", "list_files", "search_docs", "read_file", "lookup_user"):
        assert not policy.is_side_effect(name), name
        assert not policy.is_unclassified(name), name


def test_unrecognised_name_is_unclassified() -> None:
    policy = ToolPolicyConfig()
    assert policy.is_unclassified("mcp__acme__frobnicate")
    assert not policy.is_side_effect("mcp__acme__frobnicate")


def test_explicit_overrides_survive_normalisation() -> None:
    policy = ToolPolicyConfig(
        side_effect_tools=("CustomSend",),
        read_only_tools=("mcp__acme__frobnicate",),
    )
    assert policy.is_side_effect("custom_send")
    assert policy.is_side_effect("mcp__vendor__CustomSend")
    assert not policy.is_unclassified("mcp__acme__frobnicate")


def test_a_namespaced_override_does_not_grant_the_bare_name() -> None:
    """A grant scoped to one server must not classify the same name elsewhere.

    read_only_tools names acme's frobnicate. A bare frobnicate, or another
    server's, is a different tool that happens to share a word, and treating it
    as the granted one hands out the exemption to whoever picks the name.
    """
    policy = ToolPolicyConfig(read_only_tools=("mcp__acme__frobnicate",))
    assert policy.is_known_read_only("mcp__acme__frobnicate")
    assert not policy.is_known_read_only("frobnicate")
    assert not policy.is_known_read_only("mcp__other__frobnicate")


def test_a_trailing_separator_still_classifies() -> None:
    """delete_file/ is delete_file. Normalising it to "" classified it as nothing."""
    policy = ToolPolicyConfig()
    for spelling in ("delete_file", "delete_file/", "delete_file.", "delete_file:"):
        assert policy.is_side_effect(spelling), spelling


def test_a_leading_verb_is_not_discarded_by_the_namespace_split() -> None:
    """delete.file and server/delete/user are deletes wherever the host put the verb."""
    policy = ToolPolicyConfig()
    for spelling in ("delete.file", "delete/file", "exec.command", "server/delete/user"):
        assert policy.is_side_effect(spelling), spelling


def test_a_verb_prefix_does_not_match_part_of_a_word() -> None:
    """A trimmed suffix must not turn a read tool into a side effect.

    Trimming leading segments is what creates the bare string `payload` out of
    `get_payload`, so a verb stem tested against a trimmed suffix is testing a
    name nobody asked about. These are the ones this branch is responsible for.

    A name that starts with the offending word on its own, `postgres_read_query`
    against ^post, is a false positive on dev too and is left alone here rather
    than fixed by loosening a rule this branch tightened.
    """
    policy = ToolPolicyConfig()
    for spelling in (
        "get_payload",
        "list_payment_methods",
        "get_postcode",
        "get_sender_details",
        "get_rma_status",
        "get_executive_summary",
    ):
        assert not policy.is_side_effect(spelling), spelling
    assert policy.is_side_effect("slack_post_message")
    assert policy.is_side_effect("send_email")


def test_a_verb_stem_still_matches_a_longer_verb() -> None:
    """^exec means execute, ^rm means rmdir.

    Requiring every pattern to land on a token boundary read these as
    unclassified, which let the messaging profile through on `execute`. The
    boundary rule belongs on the trimmed suffixes only, not on the name the
    caller actually passed.
    """
    policy = ToolPolicyConfig()
    for spelling in (
        "execute",
        "execute_command",
        "execute_sql",
        "rmdir",
        "rmtree",
        "rmrf",
        "db_execute",
        "drop_tables",
        "run_commands",
    ):
        assert policy.is_side_effect(spelling), spelling
    assert not ToolPolicyConfig(profile="messaging").is_permitted("execute")
