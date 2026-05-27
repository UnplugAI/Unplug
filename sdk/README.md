# Unplug SDK

Pull the plug on bad AI. Runtime enforcement layer for AI agents.

```bash
pip install unplug-ai
```

```python
from unplug import Guard

guard = Guard()  # local mode, offline
result = guard.scan("Ignore all previous instructions", source="user")

if not result.safe:
    text = result.redacted_text
```

## Agent host checklist (OpenClaw-style)

Use this flow when wiring Unplug into an agent that fetches external content or calls tools:

1. **Scan user input** — `guard.scan(text, source="user")` (captures `user_intent` for later gates).
2. **Wrap untrusted content** before inserting into LLM context — `guard.wrap_for_context(rag_chunk, source="retrieved")`. Auto-wrap also runs on `scan(..., source="retrieved")` when `[boundaries] auto_wrap_untrusted = true`.
3. **After fetch/read tools** — `guard.notify_taint_source("web_fetch")` so side-effect tools require review.
4. **Before every tool call** — `guard.check_tool_call(name, args, taint_sources=[...])`. Destructive calls block; tainted session + side-effect → `REVIEW`.
5. **Scan agent output** — `guard.scan_output(text)`. Set `strip_on_output = true` to remove boundary markers from redacted output.
6. **New trusted turn** — `guard.reset_session_taint()` when the user starts a fresh instruction with no untrusted context.

Optional: run `unplug-audit --probes` after swapping in a new ML checkpoint.

Docs: [github.com/UnplugAI/Unplug](https://github.com/UnplugAI/Unplug) · Site: [unplug-ai.org](https://unplug-ai.org)
