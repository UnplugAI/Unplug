"""Optional dependency helpers — Agno-style install hints."""

from __future__ import annotations

import importlib
from typing import NoReturn


def require_extra(
    module: str,
    *,
    pip_extra: str,
    feature: str,
) -> None:
    """Import *module* or raise with a pip install hint."""
    try:
        importlib.import_module(module)
    except ImportError as exc:
        raise ImportError(
            f"{feature} requires optional dependency '{module}'.\n"
            f"Install with: pip install 'unplug-ai[{pip_extra}]'"
        ) from exc


def missing_extra_message(*, pip_extra: str, feature: str) -> str:
    return (
        f"{feature} requires optional extras.\nInstall with: pip install 'unplug-ai[{pip_extra}]'"
    )


def raise_missing_extra(*, pip_extra: str, feature: str) -> NoReturn:
    raise ImportError(missing_extra_message(pip_extra=pip_extra, feature=feature))
