"""Destructive action scanner — prevents agents from dangerous operations."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.safeguards.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "sql_drop",
        re.compile(
            r"(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b",
        ),
    ),
    ("sql_alter", re.compile(r"(?i)\b(ALTER\s+TABLE\s+\w+\s+DROP|DROP\s+COLUMN)\b")),
    ("shell_rm", re.compile(r"(?i)\b(rm\s+-rf|rm\s+-r\s|rmdir|shutil\.rmtree|os\.remove)\b")),
    ("shell_kill", re.compile(r"(?i)\b(kill\s+-9|killall|pkill|shutdown|reboot|halt)\b")),
    ("shell_format", re.compile(r"(?i)\b(mkfs|fdisk|format\s+[A-Z]:)\b")),
    ("file_delete", re.compile(r"(?i)\b(os\.unlink|os\.rmdir|pathlib.*\.unlink|shutil\.rmtree)\b")),
    ("api_delete", re.compile(r"(?i)(DELETE\s+/|\.delete\(|requests\.delete|httpx\.delete)\b")),
    (
        "git_destructive",
        re.compile(
            r"(?i)\b(git\s+(push\s+--force|reset\s+--hard|clean\s+-fd|branch\s+-D))\b",
        ),
    ),
    # NeMo Guardrails injection_detection YARA + SQLi corpora
    (
        "sql_union_injection",
        re.compile(r"(?i)\b(UNION\s+SELECT|OR\s+1\s*=\s*1|'?\s*OR\s+'1'\s*=\s*'1)\b"),
    ),
    (
        "sql_comment_injection",
        re.compile(r"(?i)(--[^\r\n]+|;\s*--|/\*[^\r\n*]+\*/)\s*(SELECT|DROP|DELETE|UNION)"),
    ),
    (
        "sql_exec",
        re.compile(r"(?i)\b(EXEC(\s|\()|EXECUTE\s+(IMMEDIATE|PROCEDURE))\b"),
    ),
    (
        "sql_system_catalog",
        re.compile(r"(?i)\b(FROM|INTO)\s+pg_\w+\b"),
    ),
    (
        "python_shell_import",
        re.compile(
            r"(?i)\b(from|import)\s+(os|subprocess|shutil|cmd|pty)\b",
        ),
    ),
    (
        "python_net_import",
        re.compile(
            r"(?i)\b(from|import)\s+"
            r"(socket|asyncio|http|requests|urllib|mechanize|asyncssh|bs4)\b",
        ),
    ),
    (
        "python_code_exec",
        re.compile(
            r"(?i)\b(eval\s*\(|exec\s*\(|__import__\s*\(|compile\s*\()",
        ),
    ),
    (
        "path_traversal",
        re.compile(r"(?:\.\.(?:/|\\)){1,}"),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.90)


class DestructiveScanner(RegexScanner):
    name = "destructive"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        normalized = norm_result.text
        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                score = self._compute_score(subcategory, text)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=score,
                    evidence=self._make_evidence(subcategory),
                    replacement=self._get_replacement(subcategory),
                )

    def _make_evidence(self, subcategory: str) -> str:
        return f"Destructive operation detected: {subcategory}"
