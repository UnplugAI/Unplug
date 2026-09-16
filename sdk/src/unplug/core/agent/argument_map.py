"""Map offsets in the joined tool-argument scan text back to individual arguments.

Tool arguments are flattened into one string before scanning, because the
patterns that matter here match a label next to its value and splitting the
arguments apart would hide those pairs from the regex. The cost of joining is
that a finding's span points into a synthetic string and says nothing about
which argument actually carried the match. This module records where each
argument landed in that string so the span can be translated back.
"""

from __future__ import annotations

from bisect import bisect_right
from typing import Any

from pydantic import BaseModel, Field


class ArgumentSegment(BaseModel):
    """One argument's half-open span within the joined scan text."""

    model_config = {"frozen": True}

    path: str = Field(description="Dotted path to the argument, e.g. json.fields[0].v")
    start: int = Field(ge=0, description="Start offset in the joined scan text")
    end: int = Field(ge=0, description="End offset in the joined scan text, exclusive")


class ArgumentMap(BaseModel):
    """Translates joined-text offsets back to the argument they came from."""

    model_config = {"frozen": True}

    segments: tuple[ArgumentSegment, ...] = ()

    def resolve(self, offset: int) -> tuple[str, int] | None:
        """Return (path, offset within that argument), or None if unmapped.

        A span that straddles the separator between two arguments resolves to
        the segment holding its start, which is where the match began.
        """
        if not self.segments:
            return None
        starts = [segment.start for segment in self.segments]
        index = bisect_right(starts, offset) - 1
        if index < 0:
            return None
        segment = self.segments[index]
        if offset >= segment.end:
            return None
        return segment.path, offset - segment.start


def _quote(key: str) -> str:
    """Bracket-quote a key that would be ambiguous in a dotted path."""
    if any(char in key for char in ".[]"):
        escaped = key.replace('"', '\\"')
        return f'["{escaped}"]'
    return f".{key}"


def _walk(value: Any, path: str, out: list[tuple[str, str]]) -> None:
    if isinstance(value, str):
        out.append((path, value))
    elif isinstance(value, dict):
        for key, child in value.items():
            suffix = _quote(str(key))
            child_path = f"{path}{suffix}" if path else suffix.lstrip(".")
            _walk(child, child_path, out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", out)


def build_argument_text(tool_name: str, arguments: dict[str, Any]) -> tuple[str, ArgumentMap]:
    """Join the tool name and every string argument, recording each one's span.

    The returned string is identical to `" ".join([tool_name, *string_values])`,
    which is what the pipeline scanned before this map existed.
    """
    parts: list[tuple[str, str]] = [("tool_name", tool_name)]
    _walk(arguments, "", parts)

    segments: list[ArgumentSegment] = []
    cursor = 0
    for path, value in parts:
        segments.append(ArgumentSegment(path=path, start=cursor, end=cursor + len(value)))
        cursor += len(value) + 1  # the joining space

    text = " ".join(value for _, value in parts)
    return text, ArgumentMap(segments=tuple(segments))
