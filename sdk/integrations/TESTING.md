# Integration security matrix

Unplug integration tests cover **72 attack angles** across hook points and framework adapters. The matrix lives in:

```
tests/security/test_agent_integration_matrix.py
```

Run locally (regex-only core, no agent SDK installs required):

```bash
cd sdk
uv run pytest tests/security/test_agent_integration_matrix.py -v
```

Run the full hook + adapter suite:

```bash
uv run pytest tests/integration/test_integrations.py tests/unit/integrations/ -v
```

## Matrix (72 angles)

| # | Category | Scenario | Expected |
|---|----------|----------|----------|
| 1 | User input | Benign question | Allow |
| 2 | User input | Direct injection ("ignore previous instructions") | Block |
| 3 | User input | System prompt exfiltration | Block |
| 4 | User input | DAN-style jailbreak | Block / review |
| 5 | User input | Fake system delimiter | Block |
| 6 | RAG ingest | Poisoned document at write time | Block ingest |
| 7 | RAG ingest | Clean document | Allow ingest |
| 8 | RAG retrieve | Injection in retrieved chunk | Drop / redact |
| 9 | RAG retrieve | Benign retrieved chunk | Wrap + keep |
| 10 | RAG retrieve | Web-sourced external metadata | Flag external trust |
| 11 | Tool | `rm -rf /` shell | Block |
| 12 | Tool | SQL DROP TABLE | Block |
| 13 | Tool | `git push --force` | Block |
| 14 | Tool | File delete path | Block |
| 15 | Tool | Benign search query | Allow |
| 16 | Tool | High-value wire transfer | Block / review |
| 17 | Output | API key in model output | Block / redact |
| 18 | Output | Benign factual answer | Allow |
| 19 | Output | Injection echoed in response | Block |
| 20 | Session | Taint after web fetch blocks risky tool | Block |
| 21 | Session | Isolated scan ignores prior taint | Allow benign |
| 22 | Session | `reset_session` clears taint | Tool allowed after reset |
| 23 | LangGraph | Input node benign | Pass state |
| 24 | LangGraph | Input node injection | RuntimeError |
| 25 | LangGraph | Tool guard destructive | Not allowed |
| 26 | Agno | Pre-run benign | No raise |
| 27 | Agno | Pre-run injection | RuntimeError |
| 28 | Agno | Post-run leak | Block |
| 29 | CrewAI | Task input injection | RuntimeError |
| 30 | CrewAI | Tool guard destructive | Not allowed |
| 31 | AutoGen | User message injection | RuntimeError |
| 32 | AutoGen | Tool guard destructive | Not allowed |
| 33 | LlamaIndex | Postprocessor drops poison node | Empty / filtered |
| 34 | LlamaIndex | Postprocessor keeps benign node | Kept |
| 35 | Pydantic AI | Input validator injection | RuntimeError |
| 36 | Semantic Kernel | Prompt filter injection | RuntimeError |
| 37 | Haystack | Ingest gate poison | Not index_ok |
| 38 | Haystack | scan_document drops block | Dropped |
| 39 | Hooks | wrap_retrieved blocked placeholder | Non-empty safe text |
| 40 | Hooks | Secret-shaped user input | Block / redact |
| 41 | OpenAI Agents | Input guardrail injection | Tripwire |
| 42 | OpenAI Agents | Output guardrail secret leak | Tripwire |
| 43 | OpenAI Agents | Tool guard destructive shell | Not allowed |
| 44 | LangChain | Input Runnable guard injection | RuntimeError |
| 45 | LangChain | Output Runnable guard secret leak | RuntimeError |
| 46 | LangChain | Tool guard SQL DROP | Not allowed |
| 47 | Google ADK | `before_model` scan injection | Blocked |
| 48 | Google ADK | `before_tool` destructive | Block dict |
| 49 | Google ADK | Extract user text from `LlmRequest` | Parsed text |
| 50 | smolagents | Task gate injection | RuntimeError |
| 51 | smolagents | `final_answer_checks` secret leak | RuntimeError |
| 52 | smolagents | Tool guard destructive shell | Not allowed |
| 53 | DSPy | Input guard injection | RuntimeError |
| 54 | DSPy | Output guard secret leak | RuntimeError |
| 55 | DSPy | Tool guard destructive shell | Not allowed |
| 56 | DSPy | `dspy_guard_tool` wrap destructive call | RuntimeError |
| 57 | Strands | Input guard injection | RuntimeError |
| 58 | Strands | Tool guard destructive shell | Not allowed |
| 59 | Strands | `HookProvider` cancels destructive tool | `cancel_tool` set |
| 60 | Letta | Input guard injection | RuntimeError |
| 61 | Letta | Tool guard destructive shell | Not allowed |
| 62 | Letta | `scan_letta_response` secret leak | Block / redact |
| 63 | Griptape | Input guard injection | RuntimeError |
| 64 | Griptape | Tool guard destructive shell | Not allowed |
| 65 | Griptape | `unplug_before_run` injected task input | RuntimeError |
| 66 | Griptape | `unplug_after_run` secret leak in output | RuntimeError |
| 67 | AG2 | `process_last_received_message` injection | RuntimeError |
| 68 | AG2 | `process_message_before_send` secret leak | RuntimeError |
| 69 | AG2 | Tool guard destructive shell | Not allowed |
| 70 | Atomic Agents | `atomic_scan_input` injection | RuntimeError |
| 71 | Atomic Agents | Tool guard destructive shell | Not allowed |
| 72 | Atomic Agents | `atomic_scan_output` secret leak | RuntimeError |

## Two layers of coverage

| Layer | What it proves | Frameworks installed? |
|-------|----------------|-----------------------|
| **Matrix** (`tests/security/test_agent_integration_matrix.py`) | The 72 attack angles + our adapter callables behave correctly | No — regex core only |
| **Live** (`tests/optional/live/test_<framework>_live.py`) | Each adapter works against the *real* installed framework (e.g. a compiled LangGraph graph, a real LlamaIndex `TextNode`, a real SK `Kernel`) | Yes — one extra per run |

The matrix is framework-agnostic and always runs. The live tests `importorskip` their
framework, so they **skip** in the core CI matrix and only execute where the framework is
installed.

## Live framework tests

These run in the dedicated **`Integrations (live)`** workflow
(`.github/workflows/integrations-live.yml`): a per-framework matrix where each leg installs
*one* extra in isolation. It triggers on PRs that touch `sdk/src/unplug/integrations/**`,
nightly (06:00 UTC), and via manual dispatch — keeping the everyday PR gate fast while
still catching framework drift.

Run one framework locally (installs just that extra):

```bash
cd sdk
uv sync --extra dev --extra langgraph
uv run pytest -q -m requires_integrations tests/optional/live/test_langgraph_live.py
```

Run every live test you have frameworks for (installs all agent SDKs):

```bash
uv sync --extra dev --extra integrations
uv run pytest -q -m requires_integrations tests/optional/live/
```

> Live tests never call an LLM. They build the smallest real framework object and assert the
> Unplug guard's decision (block on injection / destructive tool, allow benign), so they stay
> hermetic and need no API keys.

**Tolerated skips.** Each leg installs its framework, so a test that runs and fails is a real
regression. But some optional frameworks ship releases that are unimportable under our pinned
core deps (e.g. a `semantic-kernel` build that imports `Url` from `pydantic.networks`, removed
in Pydantic v2). When that happens the module `importorskip`s, pytest exits `5` ("no tests
ran"), and the job emits a non-blocking `::warning::` rather than failing — that is an upstream
conflict, not an Unplug bug. Genuine test failures (exit `1`) still fail the job.

## CI markers

| Marker | When |
|--------|------|
| *(none)* | Regex core — always runs |
| `@pytest.mark.requires_ml` | ML recall-gate probes |
| `@pytest.mark.requires_integrations` | Live tests that import a real agent SDK (`tests/optional/live/`) |

## Adding a case

1. Add a row to the table above.
2. Add a parametrized entry or test method in `test_agent_integration_matrix.py`.
3. Keep payloads in `_FIXTURES` at the top of the test file for reuse.
