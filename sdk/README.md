# Unplug SDK

Runtime enforcement layer for AI agents — provenance-aware scanning and tool-call gates.

**PyPI release follows a satisfactory unplug-tiny model run.** Until then, install from source:

```bash
git clone https://github.com/UnplugAI/Unplug.git && cd Unplug/sdk
uv sync && uv pip install -e .
```

```bash
pip install unplug-ai   # coming to PyPI after model validation
```

```python
from unplug import Guard
from unplug.api.enums import Source

guard = Guard()  # local mode, offline, regex scanners by default

result = guard.scan("Ignore all previous instructions", source="user")
if not result.safe:
    print(result.redacted_text)
    print(result.findings)
```

## Agent host checklist

Use this flow when wiring Unplug into an agent that fetches external content or calls tools:

1. **Scan user input** — `guard.scan(text, source="user")` (captures `user_intent` for later gates).
2. **Wrap untrusted content** before inserting into LLM context — `guard.wrap_for_context(rag_chunk, source="retrieved")`. Auto-wrap also runs on `scan(..., source="retrieved")` when `[boundaries] auto_wrap_untrusted = true`.
3. **After fetch/read tools** — `guard.notify_taint_source("web_fetch")` so side-effect tools require review.
4. **Before every tool call** — `guard.check_tool_call(name, args, taint_sources=[...])`. Destructive calls block; tainted session + side-effect → `REVIEW`.
5. **Scan agent output** — `guard.scan_output(text)`. Set `strip_on_output = true` to remove boundary markers from redacted output.
6. **New trusted turn** — `guard.reset_session_taint()` when the user starts a fresh instruction with no untrusted context.

Copy `unplug.example.toml` to `unplug.toml` to customize scanners, tool profiles, and boundaries.

## Optional ML (0.2.0)

```bash
pip install "unplug-ai[ml]"
```

Set `active_model = "small"` in config and point `UNPLUG_MODEL_PATH` at a DeBERTa-v3-xsmall
dual-head checkpoint (HuggingFace download in 0.2.0). The model has two heads on one backbone:
a document classifier (injection detection recall) and a token/BIOES span head (localization
and redaction). Until then, regex + tool enforcement is the supported default.

All published model metrics are produced by the frozen golden eval harness
(`unplug_exp/scripts/golden_eval.py`) on held-out data and recorded in `BENCHMARKS.md` — no
hand-typed numbers, measured not target.

Run wiring checks anytime:

```bash
unplug-audit
unplug-audit --probes          # FP + encoding + boundary batteries
unplug-audit --require-ml      # after ML checkpoint is configured
```

Dual-head integration steps and checkpoint layout: [`docs/ML_INTEGRATION.md`](docs/ML_INTEGRATION.md).

Gate numbers ship in `BENCHMARKS.md` after the golden eval harness passes on held-out data.

## Examples

- [`examples/agent_exfil_demo.py`](examples/agent_exfil_demo.py) — hidden injection → tainted session → blocked exfil tool call

Docs: [github.com/UnplugAI/Unplug](https://github.com/UnplugAI/Unplug)
