"""USER-trust input scanning for secret-shaped leakage patterns."""

from __future__ import annotations

from unplug import Guard


def test_user_input_api_key_detected_when_enabled() -> None:
    guard = Guard()
    result = guard.scan("my key is sk-abcdefghijklmnopqrstuvwxyz1234567890")
    assert any(f.category == "leakage" for f in result.findings)
