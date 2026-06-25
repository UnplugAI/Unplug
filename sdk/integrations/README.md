# Agent framework integrations

Unplug ships **framework-agnostic hooks first**. You do not need LangGraph, CrewAI, or any agent SDK to use the core Guard — install only the extra for the stack you run.

## Quick start

```bash
pip install unplug-ai                    # core Guard (regex scanners, no agent deps)
pip install "unplug-ai[langgraph]"       # + LangGraph when you wire graph nodes
pip install "unplug-ai[integrations]"    # all documented agent/RAG extras
pip install "unplug-ai[all]"             # integrations + ML + presidio + yara + …
```

Every integration module lives under `unplug.integrations.*` and uses the same five hook points:

| Hook | When to call | Threats caught |
|------|----------------|----------------|
| `scan_user_input` | Before the LLM turn | Direct prompt injection, jailbreaks |
| `wrap_retrieved_content` | After RAG / web fetch | Indirect injection in documents |
| `before_tool_call` | Before every tool | Destructive shell/SQL, exfil, financial |
| `scan_agent_output` | Before returning to user | Leaked secrets, harmful content |
| `scan_request_isolated` | Eval / probes | Same scans without session taint bleed |

```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard())  # or Guard(mode="server") for hosted API
decision = hooks.scan_user_input(user_message)
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Supported frameworks

| Framework | Extra | Guide | Code module |
|-----------|-------|-------|-------------|
| **Custom loop** | *(none)* | [custom-loop](custom-loop/README.md) | `hooks.py` |
| **LangGraph** | `langgraph` | [langgraph](langgraph/README.md) | `langgraph.py` |
| **Agno** | `agno` | [agno](agno/README.md) | `agno.py` |
| **Haystack** | `haystack` | [haystack](haystack/README.md) | `haystack.py` |
| **LlamaIndex** | `llama-index` | [llama-index](llama-index/README.md) | `llama_index.py` |
| **CrewAI** | `crewai` | [crewai](crewai/README.md) | `crewai.py` |
| **AutoGen** | `autogen` | [autogen](autogen/README.md) | `autogen.py` |
| **Pydantic AI** | `pydantic-ai` | [pydantic-ai](pydantic-ai/README.md) | `pydantic_ai.py` |
| **Semantic Kernel** | `semantic-kernel` | [semantic-kernel](semantic-kernel/README.md) | `semantic_kernel.py` |
| **MCP clients** | `mcp` | [mcp](mcp/README.md) | [unplug-mcp](https://github.com/UnplugAI/unplug-mcp) |

Demos (no framework install required for LangGraph / Agno patterns):

```bash
cd sdk
python examples/langgraph_hooks_demo.py
python examples/agno_hooks_demo.py
```

## Deployment modes

| Mode | Guard init | Tool enforcement |
|------|------------|------------------|
| Embedded (local) | `Guard()` | Local `check_tool_call` |
| Hosted API | `Guard(mode="server", server_url=..., server_api_key=...)` | **Always local** — never delegate tool policy to the network |
| Sidecar | `Guard(mode="server", server_url="http://127.0.0.1:8000")` | Local |

See [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).

## Security testing

We maintain a **40-angle integration security matrix** exercised in CI. See [TESTING.md](TESTING.md) for the full list and how to run it locally:

```bash
cd sdk
uv run pytest tests/security/test_agent_integration_matrix.py -v
```

## Contributing a new integration

1. Copy [`_template.md`](_template.md)
2. Add hooks in `src/unplug/integrations/<name>.py` (no hard dependency at import time)
3. Add optional extra in `pyproject.toml`
4. Add matrix cases in `tests/security/test_agent_integration_matrix.py`
5. Link from this README

## Related docs

- [`docs/INTEGRATIONS.md`](../docs/INTEGRATIONS.md) — API reference (compact)
- [`docs/RAG_DEFENSE.md`](../docs/RAG_DEFENSE.md) — retrieval-path threat model
- [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) — local vs hosted vs sidecar
