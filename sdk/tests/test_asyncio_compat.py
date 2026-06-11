"""Tests for sync/async bridge helpers."""

from __future__ import annotations

import asyncio

from unplug.core.asyncio_compat import run_coroutine_sync


async def _return_value(value: str) -> str:
    return value


class TestRunCoroutineSync:
    def test_runs_without_active_loop(self) -> None:
        assert run_coroutine_sync(_return_value("ok")) == "ok"

    def test_runs_from_active_loop_thread(self) -> None:
        async def _runner() -> str:
            return run_coroutine_sync(_return_value("nested"))

        assert asyncio.run(_runner()) == "nested"
