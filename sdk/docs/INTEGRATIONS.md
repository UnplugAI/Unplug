# Agent framework integrations

> **Full guides:** [`integrations/README.md`](../integrations/README.md) — per-framework wiring, extras, and the [52-angle security matrix](../integrations/TESTING.md).

Unplug ships **framework-agnostic hooks** first. Install only the extra for your stack:

```bash
pip install unplug-ai                      # core — no agent SDK deps
pip install "unplug-ai[langgraph]"         # LangGraph
pip install "unplug-ai[crewai]"            # CrewAI
pip install "unplug-ai[integrations]"      # all documented agent/RAG extras
```

## Core: `AgentHooks`

```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard())  # or Guard(mode="server") for hosted API

decision = hooks.scan_user_input("user message")
if not decision.allowed:
    raise RuntimeError(decision.message)

wrapped, rag_decision = hooks.wrap_retrieved_content(webpage_html)
tool_decision = hooks.before_tool_call("send_email", {"to": "...", "body": "..."})
```

| Hook | When to call |
|------|----------------|
| `scan_user_input` | Before LLM turn |
| `wrap_retrieved_content` | After RAG / web fetch |
| `before_tool_call` | Before every tool (always local) |
| `scan_agent_output` | Before returning to user |
| `scan_request_isolated` | Eval / probes (no session bleed) |

## Framework modules

| Framework | Extra | Module |
|-----------|-------|--------|
| LangGraph | `langgraph` | `unplug.integrations.langgraph` |
| OpenAI Agents SDK | `openai-agents` | `unplug.integrations.openai_agents` |
| LangChain | `langchain` | `unplug.integrations.langchain` |
| Google ADK | `google-adk` | `unplug.integrations.google_adk` |
| smolagents | `smolagents` | `unplug.integrations.smolagents` |
| Agno | `agno` | `unplug.integrations.agno` |
| CrewAI | `crewai` | `unplug.integrations.crewai` |
| AutoGen | `autogen` | `unplug.integrations.autogen` |
| Haystack | `haystack` | `unplug.integrations.haystack` |
| LlamaIndex | `llama-index` | `unplug.integrations.llama_index` |
| Pydantic AI | `pydantic-ai` | `unplug.integrations.pydantic_ai` |
| Semantic Kernel | `semantic-kernel` | `unplug.integrations.semantic_kernel` |
| Custom loop | *(none)* | `unplug.integrations.hooks` |

## LangGraph

```python
from unplug.integrations.langgraph import langgraph_input_node, langgraph_tool_guard

graph.add_node("unplug_gate", langgraph_input_node(hooks))
tool_guard = langgraph_tool_guard(hooks)
```

Demo: `python examples/langgraph_hooks_demo.py`

## Haystack (RAG)

```python
from unplug.integrations.haystack import UnplugDocumentGuard, scan_for_ingestion
```

Install: `pip install unplug-ai[haystack]`. See [`RAG_DEFENSE.md`](RAG_DEFENSE.md).

## Hosted vs local

| Setup | Guard init |
|-------|------------|
| Hosted API | `Guard(mode="server")` + `UNPLUG_API_KEY` |
| Sidecar | `Guard(mode="server", server_url="http://127.0.0.1:8000")` |
| Embedded | `Guard()` |

Tool enforcement always runs locally. See [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Security testing

```bash
uv run pytest tests/security/test_agent_integration_matrix.py -v
```

See [`integrations/TESTING.md`](../integrations/TESTING.md) for all 52 angles.

## Docker E2E (sidecar + examples)

```bash
cd sdk && make docker-e2e
```

## MCP

For Claude / Cursor MCP server, use [`unplug-mcp`](https://github.com/UnplugAI/unplug-mcp) — see [`integrations/mcp/README.md`](../integrations/mcp/README.md).
