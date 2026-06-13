"""Optional dependency helpers: lazy import with install hints (Agno-style)."""

from __future__ import annotations

import importlib
import logging
from typing import Any, NoReturn, TypeVar

logger = logging.getLogger("unplug.optional")

T = TypeVar("T")


def install_hint(*, pip_extra: str) -> str:
    return f"pip install 'unplug-ai[{pip_extra}]'"


def log_missing(*, module: str, pip_extra: str, feature: str) -> None:
    logger.warning(
        "%s requires optional package '%s'. Install with: %s",
        feature,
        module,
        install_hint(pip_extra=pip_extra),
    )


def import_optional(module: str, *, pip_extra: str, feature: str) -> Any | None:
    """Try importing a module; log install hint and return None on failure."""
    try:
        return importlib.import_module(module)
    except ImportError:
        log_missing(module=module, pip_extra=pip_extra, feature=feature)
        return None


def require_module(module: str, *, pip_extra: str, feature: str) -> Any:
    """Import module or raise ImportError after logging install hint."""
    mod = import_optional(module, pip_extra=pip_extra, feature=feature)
    if mod is None:
        raise_missing(pip_extra=pip_extra, feature=feature)
    return mod


def import_attr(
    module: str,
    attr: str,
    *,
    pip_extra: str,
    feature: str,
) -> Any | None:
    """Import ``attr`` from ``module``; log and return None if extra missing."""
    mod = import_optional(module, pip_extra=pip_extra, feature=feature)
    if mod is None:
        return None
    return getattr(mod, attr)


def require_attr(
    module: str,
    attr: str,
    *,
    pip_extra: str,
    feature: str,
) -> Any:
    """Import attribute or raise after logging install hint."""
    value = import_attr(module, attr, pip_extra=pip_extra, feature=feature)
    if value is None:
        raise_missing(pip_extra=pip_extra, feature=feature)
    return value


def missing_extra_message(*, pip_extra: str, feature: str) -> str:
    return f"{feature} requires optional extras.\nInstall with: {install_hint(pip_extra=pip_extra)}"


def raise_missing(*, pip_extra: str, feature: str) -> NoReturn:
    raise ImportError(missing_extra_message(pip_extra=pip_extra, feature=feature))


def require_extra(
    module: str,
    *,
    pip_extra: str,
    feature: str,
) -> None:
    """Import *module* or raise with a pip install hint (legacy API)."""
    require_module(module, pip_extra=pip_extra, feature=feature)


def raise_missing_extra(*, pip_extra: str, feature: str) -> NoReturn:
    raise_missing(pip_extra=pip_extra, feature=feature)
