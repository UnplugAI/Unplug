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
4. **Before every tool call** — `guard.check_tool_call(name, args, taint_sources=[...])`. Destructive calls block; tainted session + side-effect → `REVIEW`; crescendo triggers adaptive tightening of `exec` / `web_fetch` / browser tools (`[degradation]`).
5. **Scan agent output** — `guard.scan_output(text)`. Set `strip_on_output = true` to remove boundary markers from redacted output.
6. **New trusted turn** — `guard.reset_session_taint()` clears taint and homeostasis degradation.

- **Context files (Hermes Agent)** — `guard.scan_context_file(agents_md_text, filename="AGENTS.md")` before loading into the system prompt.

See `docs/HERMES_AGENT_SECURITY.md` and `docs/AGENT_FLOW_SECURITY.md`.

Copy `unplug.example.toml` to `unplug.toml` to customize scanners, tool profiles, and boundaries.

## Deployment modes

Three paths — full architecture in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md):

| Path | Who runs ML | Customer setup |
|------|-------------|----------------|
| **Hosted** | Unplug API (your VM + API key) | `Guard(mode="server")` only |
| **Local embedded** | Inside the SDK process | `pip install unplug-ai[ml]` + checkpoint |
| **Local sidecar** | Customer's local `unplug-server` | Docker sidecar + `Guard(mode="server")` → localhost |

**Hosted is the default for production.** Customers do not install `unplug-server` — they use an API key against your deployment.

**Local embedded** is the simplest offline path: one Python agent, model loads in-process.

**Local sidecar** reuses the same HTTP API as hosted, but the customer runs `unplug-server` on localhost (no API key). Use when multiple agents should share one model load or when you want identical wire format as hosted.

```bash
unplug-sidecar doctor   # verify localhost sidecar before starting agents
```

| Mode | When to use | Init | ML runs where |
|------|-------------|------|---------------|
| **Hosted** | Production, no GPU | `Guard(mode="server")` or TOML `mode="server"` | Unplug API |
| **Local regex** | Dev, air-gapped, zero deps | `Guard()` default | Nowhere |
| **Local + ML** | Single agent, offline BYO checkpoint | `pip install unplug-ai[ml]` + `active_model="tiny"` | Client process |
| **Local sidecar** | Multi-agent local, shared GPU | Sidecar + `Guard(mode="server")` → localhost | Local server |

### Hosted (API key → server)

```bash
export UNPLUG_SERVER_URL=https://api.your-unplug-host.com
export UNPLUG_API_KEY=up_live_xxxxxxxx
```

```python
from unplug import Guard

guard = Guard(mode="server")  # or server_url= / server_api_key= in ctor
result = guard.scan(user_text)
```

Server handles `/v1/scan` and `/v1/scan/output`. **`check_tool_call()` always runs locally** (toolchain, collusion, taint) — there is no `/v1/toolcall` endpoint yet.

See [`examples/hosted_client.py`](examples/hosted_client.py).

### Local sidecar (optional)

Same API as hosted, run locally without an API key — see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md):

```bash
# Terminal 1 — from unplug-server repo
docker compose -f docker-compose.sidecar.yml up

# Terminal 2
export UNPLUG_SERVER_URL=http://127.0.0.1:8000
unplug-sidecar doctor
python examples/local_sidecar_client.py
```

### Local regex (default)

```python
guard = Guard()  # injection, destructive, leakage, harmful — no torch required
```

### Local + ML (`unplug-tiny`)

```bash
pip install "unplug-ai[ml]"
unplug-models download tiny   # or export UNPLUG_MODEL_PATH=.../checkpoint-66630
```

```toml
# unplug.toml
active_model = "tiny"
auto_download_model = true
require_ml = true   # optional fail-fast at init
```

**Quickest path** — downloads `Unplug-AI/unplug-tiny-v1` from Hugging Face on first scan:

```python
from unplug import Guard

guard = Guard.with_tiny()  # active_model=tiny, auto_download_model=true
result = guard.scan(user_text)
```

**Long documents** (8K+ chars): sliding windows (2048 chars, 256 overlap) cover the full text — not head/tail only. Configure via `[catalog.tiers.tiny.config]` in `catalog.toml` or `unplug.toml`.

**Streaming LLM output:**

```python
scanner = guard.stream_scanner(scan_every_chars=1024)
for chunk in token_stream:
    if hit := scanner.push(chunk):
        handle(hit)
result = scanner.flush()
# Or scan a finished chunk list:
guard.scan_stream(["part1", "part2", "part3"])
```

| Variable | Hosted | Local ML |
|----------|--------|----------|
| `UNPLUG_SERVER_URL` | required | — |
| `UNPLUG_API_KEY` | required if server auth on | — |
| `UNPLUG_ACTIVE_MODEL` | — | `tiny` |
| `UNPLUG_MODEL_PATH` | — | checkpoint dir |
| `UNPLUG_REQUIRE_ML` | — | optional |

Validation manifest: [`configs/ml_validation.json`](configs/ml_validation.json) pins checkpoint-66630 and v13 thresholds.

Framework integrations (LangGraph, Agno): [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

Docker E2E (sidecar + examples): `make docker-e2e`

## Module layout

Threat scanners live under **`unplug.safeguards`** (canonical). The older `unplug.scanners` path still works but emits deprecation warnings — update imports to:

```python
from unplug.safeguards.injection import InjectionScanner
from unplug.safeguards.destructive import DestructiveScanner
from unplug.safeguards.registry import SafeguardRegistry
```

ML span detection: `unplug.safeguards.injection_ml.InjectionSpanScanner` (wired when `active_model` is set).

## Development

```bash
cd sdk && uv sync --all-extras --dev

make fix          # auto-fix lint + format
make check        # lint + format --check + full pytest
make check-ci     # CI parity: check + exfil demo + security regression
make test-security
make audit        # unplug-audit wiring
make audit-ml     # unplug-audit --require-ml
```

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`docs/SDK_HARDENING_PLAN.md`](docs/SDK_HARDENING_PLAN.md).

## Optional ML (dual-head `unplug-tiny`)

```bash
pip install "unplug-ai[ml]"
unplug-models download tiny   # once — cached under ~/.cache/unplug/models/
```

```toml
# unplug.toml
active_model = "tiny"
auto_download_model = true
require_ml = true
```

Set `active_model = "tiny"` and a checkpoint path (`UNPLUG_MODEL_PATH` or `unplug-models download`).
`UNPLUG_MODEL_PATH` alone auto-selects the `tiny` tier; prefer setting both explicitly in production.

The dual-head checkpoint has a document classifier (recall) and a BIOES span head (localization
and redaction). Without a loaded checkpoint, regex + tool enforcement remain the default.

**Optional BYOLLM judge** (SDK smoke testing, not production default):

```bash
pip install "unplug-ai[litellm]"
```

See `docs/SDK_HARDENING_PLAN.md` and `docs/ML_INTEGRATION.md`.

All published model metrics are produced by the frozen golden eval harness
(`unplug_exp/scripts/golden_eval.py`) on held-out data and recorded in `BENCHMARKS.md` — no
hand-typed numbers, measured not target.

Run wiring checks anytime:

```bash
unplug-audit                   # wiring + informational ML status
unplug-audit --probes          # FP + encoding + boundary batteries
unplug-audit --require-ml      # fail if checkpoint / config / ML not active
```

**ML status checks** (always printed; only gate `--require-ml`):

| Check | Meaning |
|-------|---------|
| `ml_checkpoint` | Checkpoint dir found on disk |
| `ml_configured` | `active_model` set in config |
| `ml_active` | `injection_ml` loaded and weights ready |

Dual-head integration steps and checkpoint layout: [`docs/ML_INTEGRATION.md`](docs/ML_INTEGRATION.md).

Gate numbers ship in `BENCHMARKS.md` after the golden eval harness passes on held-out data.

## Examples

- [`examples/agent_exfil_demo.py`](examples/agent_exfil_demo.py) — hidden injection → tainted session → blocked exfil tool call

Docs: [github.com/UnplugAI/Unplug](https://github.com/UnplugAI/Unplug)
