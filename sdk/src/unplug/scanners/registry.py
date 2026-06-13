"""Scanner registry for dynamic loading."""

from __future__ import annotations

from collections.abc import Callable

from unplug.core.config import ScannerConfig
from unplug.core.runtime.stats import MetricsCollector
from unplug.scanners.base import BaseScanner

_FACTORIES: dict[str, Callable[..., BaseScanner]] = {}


def _register_builtins() -> None:
    from unplug.scanners.destructive import DestructiveScanner
    from unplug.scanners.financial import FinancialScanner
    from unplug.scanners.harmful import HarmfulScanner
    from unplug.scanners.injection import InjectionScanner
    from unplug.scanners.leakage import LeakageScanner
    from unplug.scanners.secrets import SecretsScanner
    from unplug.scanners.urls import MaliciousUrlScanner

    _FACTORIES.update(
        {
            "injection": InjectionScanner,
            "destructive": DestructiveScanner,
            "leakage": LeakageScanner,
            "harmful": HarmfulScanner,
            "financial": FinancialScanner,
            "secrets": SecretsScanner,
            "urls": MaliciousUrlScanner,
        }
    )
    from unplug.scanners.injection_ml import InjectionSpanScanner
    from unplug.scanners.yara_scanner import YaraCodeScanner

    _FACTORIES["injection_ml"] = InjectionSpanScanner
    _FACTORIES["yara"] = YaraCodeScanner

    from unplug.scanners.pii import PresidioPiiScanner

    _FACTORIES["pii"] = PresidioPiiScanner


class ScannerRegistry:
    """Central registry for creating and caching scanner instances."""

    def __init__(self, metrics: MetricsCollector | None = None) -> None:
        self._metrics = metrics
        self._instances: dict[str, BaseScanner] = {}
        if not _FACTORIES:
            _register_builtins()

    @staticmethod
    def register(name: str, factory: Callable[..., BaseScanner]) -> None:
        _FACTORIES[name] = factory

    @staticmethod
    def available() -> list[str]:
        if not _FACTORIES:
            _register_builtins()
        return list(_FACTORIES.keys())

    def get(
        self,
        name: str,
        config: ScannerConfig | None = None,
        **kwargs: object,
    ) -> BaseScanner | None:
        if name in self._instances:
            return self._instances[name]

        if not _FACTORIES:
            _register_builtins()

        factory = _FACTORIES.get(name)
        if factory is None:
            return None

        instance = factory(config=config, metrics=self._metrics, **kwargs)
        self._instances[name] = instance
        return instance

    def get_many(
        self,
        names: list[str],
        configs: dict[str, ScannerConfig] | None = None,
    ) -> list[BaseScanner]:
        from unplug.exceptions import ConfigError

        scanners: list[BaseScanner] = []
        missing: list[str] = []
        for name in names:
            cfg = (configs or {}).get(name)
            scanner = self.get(name, config=cfg)
            if scanner is None:
                missing.append(name)
            else:
                scanners.append(scanner)
        if missing:
            msg = f"Unknown scanners: {', '.join(sorted(missing))}"
            raise ConfigError(msg)
        return scanners


def __getattr__(name: str) -> type[ScannerRegistry]:
    # Backward-compatible alias (deprecated in v0.4, remove in v1.0).
    if name == "SafeguardRegistry":
        import warnings

        warnings.warn(
            "SafeguardRegistry is deprecated; use ScannerRegistry instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return ScannerRegistry
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
