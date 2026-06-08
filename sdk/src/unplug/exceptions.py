"""Unplug exceptions."""

from __future__ import annotations


class UnplugError(Exception):
    """Base exception for Unplug."""


class ScanError(UnplugError):
    """Error during scanning."""


class ServerError(UnplugError):
    """Error communicating with Unplug server."""


class ConfigError(UnplugError):
    """Invalid configuration."""


class ConfigLoadError(ConfigError):
    """Failed to load config from file or environment."""


class ModelError(UnplugError):
    """Model download, cache, or load failure."""


class ScannerError(ScanError):
    """A scanner failed during execution."""


class PipelineError(ScanError):
    """A pipeline failed during execution."""
