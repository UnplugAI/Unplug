"""SecretsRegistry and SecretsSanitizer — exact-match secret detection and redaction."""

from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel, Field

_MAX_PATTERN_LENGTH = 500
_MAX_REGISTRY_SIZE = 10_000
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")


_GENERIC_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "generic_api_key",
        re.compile(
            r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}",
        ),
    ),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("slack_token", re.compile(r"xox[bpoa]-[A-Za-z0-9\-]{10,}")),
    ("private_key_header", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
]


def _compile_user_pattern(pattern: str) -> re.Pattern[str]:
    if len(pattern) > _MAX_PATTERN_LENGTH:
        msg = f"Pattern too long: {len(pattern)} > {_MAX_PATTERN_LENGTH}"
        raise ValueError(msg)
    if _NESTED_QUANTIFIER.search(pattern):
        msg = "Pattern may cause catastrophic backtracking"
        raise ValueError(msg)
    try:
        compiled = re.compile(pattern)
        compiled.search("a" * 100)
    except re.error as exc:
        msg = f"Invalid regex pattern: {exc}"
        raise ValueError(msg) from exc
    return compiled


class SecretEntry(BaseModel):
    name: str
    value: str = Field(repr=False, exclude=True)
    source: str
    pattern: str | None = Field(default=None, exclude=True)
    compiled_pattern: Any = Field(default=None, exclude=True, repr=False)

    model_config = {"arbitrary_types_allowed": True}

    def __repr__(self) -> str:
        return f"SecretEntry(name={self.name!r}, source={self.source!r})"

    def __str__(self) -> str:
        return f"SecretEntry({self.name})"


class SecretMatch(BaseModel):
    secret_name: str
    span_start: int
    span_end: int
    source: str


class SanitizeResult(BaseModel):
    clean_text: str
    secrets_found: list[SecretMatch]


class SecretsRegistry:
    """Register and detect known secrets in text."""

    def __init__(self) -> None:
        self._secrets: dict[str, SecretEntry] = {}

    def register(
        self,
        name: str,
        value: str,
        source: str = "user",
        *,
        pattern: str | None = None,
    ) -> None:
        if not value:
            return
        if len(self._secrets) >= _MAX_REGISTRY_SIZE:
            msg = f"Registry size limit reached ({_MAX_REGISTRY_SIZE})"
            raise ValueError(msg)
        compiled_pattern = _compile_user_pattern(pattern) if pattern else None
        self._secrets[name] = SecretEntry(
            name=name,
            value=value,
            source=source,
            pattern=pattern,
            compiled_pattern=compiled_pattern,
        )

    def register_from_env(self, prefixes: list[str]) -> int:
        count = 0
        for key, value in os.environ.items():
            if any(key.startswith(p) for p in prefixes) and value:
                self.register(key, value, source="env")
                count += 1
        return count

    def contains(self, text: str) -> list[SecretMatch]:
        matches: list[SecretMatch] = []
        matched_spans: set[tuple[int, int]] = set()

        for entry in self._secrets.values():
            start = 0
            while True:
                idx = text.find(entry.value, start)
                if idx == -1:
                    break
                span = (idx, idx + len(entry.value))
                if span not in matched_spans:
                    matched_spans.add(span)
                    matches.append(
                        SecretMatch(
                            secret_name=entry.name,
                            span_start=span[0],
                            span_end=span[1],
                            source="registry_exact_match",
                        )
                    )
                start = idx + 1

            if entry.compiled_pattern is not None:
                for m in entry.compiled_pattern.finditer(text):
                    span = (m.start(), m.end())
                    if span not in matched_spans:
                        matched_spans.add(span)
                        matches.append(
                            SecretMatch(
                                secret_name=entry.name,
                                span_start=span[0],
                                span_end=span[1],
                                source="pattern_match",
                            )
                        )

        for subcategory, pat in _GENERIC_SECRET_PATTERNS:
            for m in pat.finditer(text):
                span = (m.start(), m.end())
                if not any(s <= span[0] and span[1] <= e for s, e in matched_spans):
                    matched_spans.add(span)
                    matches.append(
                        SecretMatch(
                            secret_name=subcategory,
                            span_start=span[0],
                            span_end=span[1],
                            source="generic_pattern",
                        )
                    )

        return matches

    def redact(self, text: str) -> str:
        entries = sorted(self._secrets.values(), key=lambda e: len(e.value), reverse=True)
        result = text
        for entry in entries:
            result = result.replace(entry.value, f"[REDACTED:{entry.name}]")
        return result


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not spans:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


class SecretsSanitizer:
    """Sanitizes text by replacing all detected secrets."""

    def __init__(self, registry: SecretsRegistry) -> None:
        self._registry = registry

    def sanitize(self, text: str) -> SanitizeResult:
        matches = self._registry.contains(text)
        clean = self._registry.redact(text)

        generic_spans: list[tuple[int, int]] = []
        for _subcategory, pat in _GENERIC_SECRET_PATTERNS:
            for m in pat.finditer(clean):
                generic_spans.append((m.start(), m.end()))

        for start, end in sorted(_merge_spans(generic_spans), reverse=True):
            clean = clean[:start] + "[REDACTED]" + clean[end:]

        return SanitizeResult(clean_text=clean, secrets_found=matches)
