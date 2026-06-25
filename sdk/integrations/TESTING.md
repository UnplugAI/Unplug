# Integration security matrix

Unplug integration tests cover **40 attack angles** across hook points and framework adapters. The matrix lives in:

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

## Matrix (40 angles)

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

## CI markers

| Marker | When |
|--------|------|
| *(none)* | Regex core — always runs |
| `@pytest.mark.requires_haystack` | Haystack component tests |
| `@pytest.mark.requires_ml` | ML recall-gate probes |
| `@pytest.mark.requires_integrations` | Tests that import optional agent SDKs |

## Adding a case

1. Add a row to the table above.
2. Add a parametrized entry or test method in `test_agent_integration_matrix.py`.
3. Keep payloads in `_FIXTURES` at the top of the test file for reuse.
