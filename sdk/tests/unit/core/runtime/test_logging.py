"""Tests for core/logging.py: correlation IDs and logger setup."""

from __future__ import annotations

import logging

from unplug.core.runtime.logging import (
    CorrelationFilter,
    correlation_scope,
    get_correlation_id,
    get_logger,
    set_correlation_id,
)


class TestCorrelationId:
    def test_default_is_none(self):
        assert get_correlation_id() is None

    def test_set_and_get(self):
        set_correlation_id("test-123")
        assert get_correlation_id() == "test-123"
        set_correlation_id(None)  # type: ignore[arg-type]

    def test_scope_sets_and_resets(self):
        assert get_correlation_id() is None
        with correlation_scope("req-abc"):
            assert get_correlation_id() == "req-abc"
        assert get_correlation_id() is None

    def test_scope_auto_generates(self):
        with correlation_scope() as cid:
            assert cid is not None
            assert len(cid) == 16
            assert get_correlation_id() == cid

    def test_scope_nested(self):
        with correlation_scope("outer"):
            assert get_correlation_id() == "outer"
            with correlation_scope("inner"):
                assert get_correlation_id() == "inner"
            assert get_correlation_id() == "outer"


class TestGetLogger:
    def test_namespace(self):
        logger = get_logger("test_module")
        assert logger.name == "unplug.test_module"

    def test_has_correlation_filter(self):
        logger = get_logger("filter_test")
        assert any(isinstance(f, CorrelationFilter) for f in logger.filters)

    def test_no_duplicate_filters(self):
        logger = get_logger("dup_test")
        get_logger("dup_test")
        filters = [f for f in logger.filters if isinstance(f, CorrelationFilter)]
        assert len(filters) == 1


class TestCorrelationFilter:
    def test_injects_correlation_id(self):
        filt = CorrelationFilter()
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "msg",
            (),
            None,
        )
        with correlation_scope("abc-123"):
            filt.filter(record)
        assert record.correlation_id == "abc-123"  # type: ignore[attr-defined]

    def test_default_dash_when_no_id(self):
        filt = CorrelationFilter()
        record = logging.LogRecord(
            "test",
            logging.INFO,
            "",
            0,
            "msg",
            (),
            None,
        )
        filt.filter(record)
        assert record.correlation_id == "-"  # type: ignore[attr-defined]
