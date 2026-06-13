"""Injection and jailbreak regex patterns: loaded from packaged YAML."""

from __future__ import annotations

import re

from unplug.core.pattern_loader import injection_patterns

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = injection_patterns()
