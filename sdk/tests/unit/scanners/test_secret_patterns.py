"""Secret patterns: the three anchored ones, and the benign shapes they must not match."""

from __future__ import annotations

import pytest

from unplug.core.context import ExecutionContext
from unplug.core.pattern_loader import secret_only_patterns
from unplug.core.taint import Tagger, TrustLevel
from unplug.scanners.leakage import LeakageScanner

AWS_DUMMY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS's own published example
GH_PAT = "github_pat_11ABCDE0Y0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789abcdefghijKLMNOP"


def _subcategories(text: str) -> list[str]:
    """Scan at USER trust, which is how the tool-call pipeline tags arguments."""
    scanner = LeakageScanner()
    tagged = Tagger().tag(text, TrustLevel.USER, "test")
    return [f.subcategory for f in scanner.scan(tagged, ExecutionContext())]


def _findings(text: str) -> list:
    scanner = LeakageScanner()
    tagged = Tagger().tag(text, TrustLevel.USER, "test")
    return list(scanner.scan(tagged, ExecutionContext()))


class TestAwsSecretAccessKey:
    @pytest.mark.parametrize(
        "text",
        [
            f"AWS_SECRET_ACCESS_KEY={AWS_DUMMY}",
            f'aws_secret_key: "{AWS_DUMMY}"',
            f"aws-secret-access-key = '{AWS_DUMMY}'",
        ],
    )
    def test_labelled_key_matches(self, text: str) -> None:
        assert "aws_secret_access_key" in _subcategories(text)

    def test_span_ends_at_the_key(self) -> None:
        """The match covers label plus value and stops at the value's last character."""
        text = f"AWS_SECRET_ACCESS_KEY={AWS_DUMMY} and then some trailing prose"
        finding = next(f for f in _findings(text) if f.subcategory == "aws_secret_access_key")
        assert text[finding.span_start : finding.span_end].endswith(AWS_DUMMY)

    def test_longer_value_does_not_match_a_truncated_prefix(self) -> None:
        """Without the trailing lookahead this would match the first 40 chars."""
        text = f"aws_secret_access_key_backup_b64={AWS_DUMMY}TRAILING123456789"
        assert "aws_secret_access_key" not in _subcategories(text)

    @pytest.mark.parametrize(
        "text",
        [
            "rotate the aws_secret_access_key in vault, ticket AWS-4417",
            "artifact digest 3f5a9c1e4b8d20567890abcdef1234567890abcd built ok",
            "checksum is n4bQgYhMfWWaLqgobNLhsHtcMYHTkM9RaPjBRrLWRSA=",
        ],
    )
    def test_benign_shapes_do_not_match(self, text: str) -> None:
        assert "aws_secret_access_key" not in _subcategories(text)


class TestDbConnectionString:
    @pytest.mark.parametrize(
        "text",
        [
            "postgres://svc:R3alP4ss@prod-db.internal:5432/billing",
            "postgresql://svc:R3alP4ss@prod-db.internal/billing",
            "mongodb+srv://admin:Sup3rS3cret@cluster0.example.net/prod",
            "redis://default:abc12345@cache.internal:6379/0",
            "mysql://root:hunter2000@127.0.0.1:3306/app",
        ],
    )
    def test_credentialled_dsn_matches(self, text: str) -> None:
        assert "db_connection_string" in _subcategories(text)

    @pytest.mark.parametrize(
        "text",
        [
            "postgres://app:${DB_PASSWORD}@db.internal:5432/app",
            "postgres://user:<REDACTED>@host/db",
            "postgres://user:%s@host/db",
            "postgres://user:***@host/db",
            "postgres://readonly@analytics.internal/warehouse",
        ],
    )
    def test_placeholders_and_passwordless_do_not_match(self, text: str) -> None:
        assert "db_connection_string" not in _subcategories(text)

    def test_http_basic_auth_is_out_of_scope(self) -> None:
        """Basic-auth URLs are common in fixtures; urls.yaml owns them if ever wanted."""
        assert "db_connection_string" not in _subcategories("https://user:pass@example.com/p")


class TestGithubFineGrainedPat:
    def test_token_matches(self) -> None:
        assert "github_pat_fine_grained" in _subcategories(f"token is {GH_PAT}")

    def test_bare_prefix_does_not_match(self) -> None:
        assert "github_pat_fine_grained" not in _subcategories("see github_pat_ docs")

    def test_classic_token_pattern_does_not_claim_it(self) -> None:
        assert "github_token" not in _subcategories(GH_PAT)


class TestPatternFileIntegrity:
    def test_every_pattern_compiles_and_names_are_unique(self) -> None:
        patterns = secret_only_patterns()
        names = [name for name, _ in patterns]
        assert len(names) == len(set(names)), "duplicate pattern name in secrets.yaml"
        for _, compiled in patterns:
            compiled.search("")  # a broken regex would have raised at load
