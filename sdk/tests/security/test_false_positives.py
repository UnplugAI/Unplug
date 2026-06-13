"""False positive tests: legitimate content that must pass through."""

from __future__ import annotations

import pytest

from unplug import Guard


@pytest.fixture
def guard():
    return Guard()


class TestLegitimateProgramming:
    def test_git_commands(self, guard):
        r = guard.scan("Run git pull origin main to get the latest changes")
        assert r.safe

    def test_database_queries(self, guard):
        r = guard.scan("SELECT id, name FROM users WHERE status = 'active'")
        assert r.safe

    def test_file_operations(self, guard):
        r = guard.scan("Create a new file called config.yaml in the root directory")
        assert r.safe

    def test_api_discussion(self, guard):
        r = guard.scan("The REST API returns a JSON response with status 200")
        assert r.safe


class TestLegitimateConversation:
    def test_instruction_word(self, guard):
        r = guard.scan("Follow the instructions in the README")
        assert r.safe

    def test_system_word(self, guard):
        r = guard.scan("The operating system handles memory management")
        assert r.safe

    def test_prompt_word(self, guard):
        r = guard.scan("The prompt asks users to enter their name")
        assert r.safe

    def test_role_word(self, guard):
        r = guard.scan("Your role in this project is to review PRs")
        assert r.safe

    def test_ignore_word(self, guard):
        r = guard.scan("We can safely ignore this deprecation warning")
        assert r.safe


class TestLegitimateFinancial:
    def test_price_discussion(self, guard):
        r = guard.scan("The product costs $49.99 per month")
        assert r.safe

    def test_small_transaction(self, guard):
        r = guard.scan("Process a payment of $25.00 for the subscription")
        assert r.safe


class TestLegitimateOutput:
    def test_code_with_base64(self, guard):
        r = guard.scan_output("Use base64.b64encode(data) to encode the payload")
        assert r.safe

    def test_example_emails_in_docs(self, guard):
        r = guard.scan_output("Example: the default test email placeholder in docs")
        assert r.safe
