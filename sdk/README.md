# Unplug SDK

**Unplug the bad AI.**

Find the attack. Cut the attack. Keep the rest.

Unplug is a runtime defense layer for LLM apps and agents. It tracks where every piece of text came from, scans untrusted content for prompt injection, and gates tool calls before they do damage. Attacks are redacted at the span level, so the rest of the document stays usable.

<p>
  <a href="https://github.com/UnplugAI/Unplug/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/UnplugAI/Unplug/actions/workflows/ci.yml/badge.svg?branch=dev"></a>
  <a href="https://pypi.org/project/unplug-ai/"><img alt="PyPI" src="https://img.shields.io/pypi/v/unplug-ai"></a>
  <a href="https://huggingface.co/spaces/Unplug-AI/unplug-tiny-demo"><img alt="Live demo" src="https://img.shields.io/badge/Live_demo-Hugging_Face_Space-22c55e"></a>
  <a href="https://huggingface.co/Unplug-AI/unplug-tiny-v1"><img alt="Model" src="https://img.shields.io/badge/Model-unplug--tiny--v1-f59e0b"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-9ca3af"></a>
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-3b82f6">
</p>

## Why Unplug

- **Span-level redaction.** Binary blocking throws away the whole document. Unplug localizes the injected instruction to character offsets and removes just that.
- **Provenance built in.** Nothing enters as a raw string. Every text carries its source (user, retrieved, tool output) and trust level.
- **Tool-call gates.** Destructive calls block. Tainted sessions force review before side-effect tools run.
- **Fail closed.** Scanner errors block, never silently allow.
- **Offline by default.** Regex + normalization scanning needs zero ML dependencies. One line upgrades to the ML span model.

## Install

```bash
pip install unplug-ai           # regex-only core, zero ML deps
pip install "unplug-ai[ml]"     # add the ML span model
```

Or from source:

```bash
git clone https://github.com/UnplugAI/Unplug.git && cd Unplug/sdk
uv sync && uv pip install -e ".[ml]"
```

## 60-second quickstart

```python
from unplug import Guard

guard = Guard()  # local mode, offline, regex scanners

result = guard.scan("Ignore all previous instructions", source="user")
if not result.safe:
    print(result.action)          # block / review / redact
    print(result.redacted_text)   # attack spans replaced
    print(result.findings)        # evidence with span offsets
```

Upgrade to the ML span model. Weights download once from [Unplug-AI/unplug-tiny-v1](https://huggingface.co/Unplug-AI/unplug-tiny-v1) and cache locally:

```python
guard = Guard.with_tiny()
result = guard.scan(rag_chunk, source="retrieved")
```

No install needed to try it: [live demo on Hugging Face](https://huggingface.co/spaces/Unplug-AI/unplug-tiny-demo).

## Protect an agent

Wire Unplug into any agent that fetches external content or calls tools:

1. **Scan user input.** `guard.scan(text, source="user")` captures `user_intent` for later gates.
2. **Wrap untrusted content** before it enters LLM context. `guard.wrap_for_context(rag_chunk, source="retrieved")`. Auto-wrap also runs on `scan(..., source="retrieved")` when `[boundaries] auto_wrap_untrusted = true`.
3. **After fetch/read tools.** `guard.notify_taint_source("web_fetch")` so side-effect tools require review.
4. **Before every tool call.** `guard.check_tool_call(name, args, taint_sources=[...])`. Destructive calls block. A tainted session plus a side-effect tool returns `REVIEW`. Crescendo patterns tighten `exec`, `web_fetch`, and browser tools adaptively (`[degradation]`).
5. **Scan agent output.** `guard.scan_output(text)`. Set `strip_on_output = true` to remove boundary markers from redacted output.
6. **New trusted turn.** `guard.reset_session_taint()` clears taint and degradation.

Context files (AGENTS.md and similar): `guard.scan_context_file(text, filename="AGENTS.md")` before loading into the system prompt.

Full walkthrough: [`examples/agent_exfil_demo.py`](examples/agent_exfil_demo.py) shows a hidden webpage injection leading to a tainted session and a blocked exfil tool call.

## Long documents and streams

Documents past 8K chars are scanned with sliding windows (2048 chars, 256 overlap) so the full text is covered, not just head and tail. Configure under `[catalog.tiers.tiny.config]` or `unplug.toml`.

```python
# Streamed LLM output: scan incrementally, full coverage on flush
scanner = guard.stream_scanner(scan_every_chars=1024)
for chunk in token_stream:
    if hit := scanner.push(chunk):
        handle(hit)
result = scanner.flush()

# Or scan a finished chunk list as one document
guard.scan_stream(["part1", "part2", "part3"])
```

## Deployment modes

| Mode | When to use | Init | ML runs where |
|------|-------------|------|---------------|
| **Local regex** | Dev, air-gapped, zero deps | `Guard()` | Nowhere |
| **Local + ML** | Single agent, offline | `Guard.with_tiny()` or `active_model="tiny"` | Agent process |
| **Hosted** | Production, no GPU on client | `Guard(mode="server")` + API key | Unplug API |
| **Local sidecar** | Many local agents, one model load | Sidecar + `Guard(mode="server")` to localhost | Local server |

Full architecture and decision guide: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

### Hosted

```bash
export UNPLUG_SERVER_URL=https://api.your-unplug-host.com
export UNPLUG_API_KEY=up_live_xxxxxxxx
```

```python
guard = Guard(mode="server")  # or server_url= / server_api_key= in ctor
```

The server handles `/v1/scan` and `/v1/scan/output`. `check_tool_call()` always runs locally (toolchain, collusion, taint). See [`examples/hosted_client.py`](examples/hosted_client.py).

### Local sidecar

Same wire format as hosted, run on localhost without an API key:

```bash
# Terminal 1, from the unplug-server repo
docker compose -f docker-compose.sidecar.yml up

# Terminal 2
export UNPLUG_SERVER_URL=http://127.0.0.1:8000
unplug-sidecar doctor
python examples/local_sidecar_client.py
```

## ML model: unplug-tiny

The dual-head checkpoint has a document classifier (recall) and a BIOES span head (localization and redaction). Without it, regex + tool enforcement remain the default.

```bash
pip install "unplug-ai[ml]"
unplug-models download tiny   # optional; Guard.with_tiny() auto-downloads too
```

```toml
# unplug.toml
active_model = "tiny"
auto_download_model = true
require_ml = true   # optional fail-fast at init
```

`UNPLUG_MODEL_PATH` alone auto-selects the `tiny` tier; prefer setting both explicitly in production. Checkpoint layout and integration steps: [`docs/ML_INTEGRATION.md`](docs/ML_INTEGRATION.md).

All published model metrics come from a frozen golden-eval harness on held-out data and are recorded on the [model card](https://huggingface.co/Unplug-AI/unplug-tiny-v1). No hand-typed numbers, measured not target.

Verify your wiring anytime:

```bash
unplug-audit                   # wiring + ML status
unplug-audit --probes          # FP + encoding + boundary batteries
unplug-audit --require-ml      # fail if checkpoint / config / ML not active
```

| Check | Meaning |
|-------|---------|
| `ml_checkpoint` | Checkpoint dir found on disk |
| `ml_configured` | `active_model` set in config |
| `ml_active` | `injection_ml` loaded and weights ready |

## Configuration

Copy `unplug.example.toml` to `unplug.toml` to customize scanners, tool profiles, boundaries, and limits.

| Variable | Hosted | Local ML |
|----------|--------|----------|
| `UNPLUG_SERVER_URL` | required | - |
| `UNPLUG_API_KEY` | required if server auth on | - |
| `UNPLUG_ACTIVE_MODEL` | - | `tiny` |
| `UNPLUG_MODEL_PATH` | - | checkpoint dir |
| `UNPLUG_REQUIRE_ML` | - | optional |

## Integrations

Framework hooks for LangGraph and Agno, plus framework-agnostic patterns: [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

Threat scanners live under `unplug.scanners` (canonical). The older `unplug.safeguards` path still works but emits deprecation warnings:

```python
from unplug.scanners.injection import InjectionScanner
from unplug.scanners.destructive import DestructiveScanner
from unplug.scanners.registry import ScannerRegistry
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for layering and optional extras.

## Examples

- [`examples/quickstart.py`](examples/quickstart.py): minimal local Guard scan
- [`examples/server_client.py`](examples/server_client.py): HTTP client against a running sidecar
- [`examples/agent_exfil_demo.py`](examples/agent_exfil_demo.py): hidden injection, tainted session, blocked exfil tool call
- [`examples/langgraph_hooks_demo.py`](examples/langgraph_hooks_demo.py) and [`examples/agno_hooks_demo.py`](examples/agno_hooks_demo.py): framework hooks
- [`examples/hosted_client.py`](examples/hosted_client.py) and [`examples/local_sidecar_client.py`](examples/local_sidecar_client.py): server modes
- [`demo/`](demo/): the Gradio app behind the [Hugging Face demo](https://huggingface.co/spaces/Unplug-AI/unplug-tiny-demo)

## Documentation

| Doc | Covers |
|-----|--------|
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Hosted vs embedded vs sidecar architecture |
| [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) | Regex SDK eval results (neuralchemy, microsoft) |
| [`docs/ML_INTEGRATION.md`](docs/ML_INTEGRATION.md) | Checkpoint layout, thresholds, long-text and streaming config |
| [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) | LangGraph, Agno, framework-agnostic hooks |
| [`docs/AGENT_FLOW_SECURITY.md`](docs/AGENT_FLOW_SECURITY.md) | End-to-end agent hardening flow |
| [`docs/HERMES_AGENT_SECURITY.md`](docs/HERMES_AGENT_SECURITY.md) | Context-file scanning for agent frameworks |

## Development

Supported Python versions: **3.11, 3.12, and 3.13** (CI matrix). On 3.13, the `ml` and `litellm` extras are skipped in CI until `tokenizers` publishes cp313 wheels; regex-only core and optional `presidio`/`yara`/`haystack` tests still run. Mark optional tests with `@pytest.mark.requires_ml`, `requires_presidio`, or `requires_yara`.

```bash
cd sdk && uv sync --all-extras --dev

make fix          # auto-fix lint + format
make check        # lint + format check + full pytest
make check-ci     # CI parity: check + exfil demo + security regression
make test-security
make audit        # unplug-audit wiring
make audit-ml     # unplug-audit --require-ml
```

Contributions welcome. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## License

Apache-2.0
