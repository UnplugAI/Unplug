"""Canary tokens — planted prompt markers that turn leakage into a detectable event.

Rebuff pattern: mint a random token, embed it invisibly in the system prompt,
and treat any appearance of the token in model output as proof of prompt
leakage. Detection is exact-match and offline.
"""

from __future__ import annotations

import secrets
import threading
import time

from pydantic import BaseModel, Field

from unplug.models import Finding

CANARY_NAME_PREFIX = "canary:"
_TOKEN_BYTES = 8


class CanaryRecord(BaseModel):
    """One minted canary token."""

    model_config = {"frozen": True}

    token: str = Field(min_length=16, max_length=16)
    label: str = "system_prompt"
    created_at: float = Field(default_factory=time.time)

    @property
    def registry_name(self) -> str:
        """Name for SecretsRegistry registration; excludes the full token value."""
        return f"{CANARY_NAME_PREFIX}{self.label}:{self.token[:4]}"


def mint_canary(label: str = "system_prompt") -> CanaryRecord:
    return CanaryRecord(token=secrets.token_hex(_TOKEN_BYTES), label=label)


def embed_canary(prompt: str, record: CanaryRecord) -> str:
    """Prepend the canary as an HTML comment — invisible in rendered output."""
    return f"<!-- canary {record.token} -->\n{prompt}"


def add_canary_word(
    prompt: str,
    *,
    label: str = "system_prompt",
) -> tuple[str, CanaryRecord]:
    """Mint a canary and embed it in the prompt (Rebuff's add_canary_word)."""
    record = mint_canary(label)
    return embed_canary(prompt, record), record


class CanaryRegistry:
    """Thread-safe per-session canary store with standalone detection.

    Guard registers canary values in its SecretsRegistry so the output
    pipeline catches leaks; this registry supports direct use in
    integrations that scan text without a full pipeline.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, CanaryRecord] = {}

    def add(self, record: CanaryRecord) -> None:
        with self._lock:
            self._records[record.token] = record

    def add_canary(self, prompt: str, *, label: str = "system_prompt") -> tuple[str, CanaryRecord]:
        wrapped, record = add_canary_word(prompt, label=label)
        self.add(record)
        return wrapped, record

    def records(self) -> list[CanaryRecord]:
        with self._lock:
            return list(self._records.values())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def detect(self, text: str) -> list[CanaryRecord]:
        return [r for r in self.records() if r.token in text]

    def findings(self, text: str, *, score: float = 0.99) -> list[Finding]:
        out: list[Finding] = []
        for record in self.records():
            start = text.find(record.token)
            while start != -1:
                out.append(
                    Finding(
                        category="leakage",
                        subcategory="prompt_leak_canary",
                        stage="canary",
                        span_start=start,
                        span_end=start + len(record.token),
                        score=score,
                        evidence=f"Canary token for '{record.label}' leaked into output",
                        replacement="[REDACTED:canary]",
                    )
                )
                start = text.find(record.token, start + 1)
        return out
