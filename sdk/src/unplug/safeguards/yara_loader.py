"""Compile bundled YARA rules once (optional yara-python extra)."""

from __future__ import annotations

import threading
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

_RULE_NAMES = ("code", "sqli", "template", "xss")

_lock = threading.Lock()
_rules: Any | None = None
_load_error: str | None = None


def yara_available() -> bool:
    try:
        import yara  # noqa: F401

        return True
    except ImportError:
        return False


def yara_load_error() -> str | None:
    return _load_error


@lru_cache(maxsize=1)
def _rules_dir() -> Path:
    return Path(resources.files("unplug.safeguards")).joinpath("yara_rules")


def get_yara_rules() -> Any | None:
    """Return compiled YARA rules, or None if yara-python is not installed."""
    global _rules, _load_error

    if _rules is not None:
        return _rules
    if _load_error is not None:
        return None

    with _lock:
        if _rules is not None:
            return _rules
        if _load_error is not None:
            return None

        try:
            import yara
        except ImportError:
            _load_error = "yara-python not installed (pip install 'unplug-ai[yara]')"
            return None

        rules_dir = _rules_dir()
        filepaths = {
            name: str(rules_dir / f"{name}.yara")
            for name in _RULE_NAMES
            if (rules_dir / f"{name}.yara").is_file()
        }
        if not filepaths:
            _load_error = f"no bundled YARA rules under {rules_dir}"
            return None

        try:
            _rules = yara.compile(filepaths=filepaths)
        except Exception as exc:
            _load_error = f"YARA compile failed: {type(exc).__name__}: {exc}"
            return None

        return _rules
