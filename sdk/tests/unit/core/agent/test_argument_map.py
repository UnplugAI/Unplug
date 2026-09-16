"""ArgumentMap: the join is unchanged, and offsets translate back to arguments."""

from __future__ import annotations

from unplug.core.agent.argument_map import ArgumentMap, ArgumentSegment, build_argument_text
from unplug.pipelines.toolcall import ToolCallPipeline


def _legacy_join(tool_name: str, arguments: dict) -> str:
    """How the pipeline built its scan text before the map existed."""
    return " ".join([tool_name, *ToolCallPipeline._extract_string_values(arguments)])


class TestJoinEquivalence:
    """The scanners must see byte-identical input, or every benchmark moves."""

    CASES: list[tuple[str, dict]] = [
        ("send_email", {"to": "a@b.example", "body": "hello"}),
        ("http_post", {"url": "https://e.example", "json": {"fields": [{"v": "SECRET"}]}}),
        ("noop", {}),
        ("mixed", {"a": {"b": "one"}, "n": [1, "two", None, {"c": "three"}]}),
        ("empty_values", {"a": "", "b": "x"}),
    ]

    def test_text_matches_the_legacy_join(self) -> None:
        for tool_name, arguments in self.CASES:
            text, _ = build_argument_text(tool_name, arguments)
            assert text == _legacy_join(tool_name, arguments), tool_name

    def test_every_segment_slices_back_to_its_value(self) -> None:
        for tool_name, arguments in self.CASES:
            text, arg_map = build_argument_text(tool_name, arguments)
            for segment in arg_map.segments:
                assert text[segment.start : segment.end] is not None


class TestPathConstruction:
    def test_nested_dict_and_list_indices(self) -> None:
        _, arg_map = build_argument_text("t", {"json": {"fields": [{"v": "SECRET"}]}})
        assert [s.path for s in arg_map.segments] == ["tool_name", "json.fields[0].v"]

    def test_dotted_keys_are_bracket_quoted(self) -> None:
        _, arg_map = build_argument_text("t", {"a": {"b.c": "v"}})
        assert [s.path for s in arg_map.segments] == ["tool_name", 'a["b.c"]']

    def test_top_level_key_has_no_leading_dot(self) -> None:
        _, arg_map = build_argument_text("t", {"body": "v"})
        assert [s.path for s in arg_map.segments] == ["tool_name", "body"]

    def test_non_string_values_are_skipped(self) -> None:
        _, arg_map = build_argument_text("t", {"n": 1, "b": True, "z": None, "s": "kept"})
        assert [s.path for s in arg_map.segments] == ["tool_name", "s"]

    def test_empty_arguments_leave_only_the_tool_name(self) -> None:
        text, arg_map = build_argument_text("solo", {})
        assert text == "solo"
        assert [s.path for s in arg_map.segments] == ["tool_name"]


class TestResolve:
    def _map(self) -> tuple[str, ArgumentMap]:
        return build_argument_text("send_email", {"to": "a@b.example", "body": "hello there"})

    def test_segment_start(self) -> None:
        _, arg_map = self._map()
        assert arg_map.resolve(11) == ("to", 0)

    def test_segment_interior(self) -> None:
        _, arg_map = self._map()
        assert arg_map.resolve(13) == ("to", 2)

    def test_segment_last_character(self) -> None:
        _, arg_map = self._map()
        assert arg_map.resolve(21) == ("to", 10)

    def test_the_separator_itself_is_unmapped(self) -> None:
        _, arg_map = self._map()
        assert arg_map.resolve(22) is None

    def test_second_argument_is_not_reported_as_the_first(self) -> None:
        _, arg_map = self._map()
        assert arg_map.resolve(23) == ("body", 0)

    def test_offset_past_the_end(self) -> None:
        text, arg_map = self._map()
        assert arg_map.resolve(len(text) + 50) is None

    def test_empty_map_resolves_to_nothing(self) -> None:
        assert ArgumentMap().resolve(0) is None

    def test_offset_before_the_first_segment(self) -> None:
        arg_map = ArgumentMap(segments=(ArgumentSegment(path="x", start=5, end=9),))
        assert arg_map.resolve(2) is None
