"""Latency of check_tool_call across argument sizes.

Run this on the base commit and on the branch tip in the same session: absolute
numbers move with machine load, so only the paired comparison is meaningful.
"""

from __future__ import annotations

import statistics
import time
from typing import Any

from unplug import Guard

CASES: list[tuple[str, str, dict[str, Any], int]] = [
    ("benign small", "send_email", {"to": "a@b.example", "body": "Invoice, due Friday."}, 200),
    ("108KB file content", "write_file", {"path": "x.md", "content": "lorem ipsum. " * 8000}, 50),
    ("5KB pathological", "http_post", {"url": "https://e.example", "data": "sk-" + "a" * 5000}, 50),
]


def bench(label: str, tool: str, args: dict[str, Any], iterations: int) -> None:
    """Warm once, then report p50, p99 and max over `iterations` calls."""
    guard = Guard()
    guard.check_tool_call(tool, args)
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        guard.check_tool_call(tool, args)
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    size = sum(len(str(v)) for v in args.values())
    print(
        f"{label:24} n={iterations} size={size:>7}B  "
        f"p50={statistics.median(samples):8.3f}ms  "
        f"p99={samples[int(iterations * 0.99) - 1]:8.3f}ms  max={samples[-1]:8.3f}ms"
    )


if __name__ == "__main__":
    for case in CASES:
        bench(*case)
