"""Provenance tracking: TaintedText, TrustLevel, Tagger."""

from __future__ import annotations

from unplug.core.taint.levels import TrustLevel, trust_level_from_source
from unplug.core.taint.text import Tagger, TaintedText

__all__ = ["Tagger", "TaintedText", "TrustLevel", "trust_level_from_source"]
