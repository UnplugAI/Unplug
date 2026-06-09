# Agent framework integrations

Unplug ships **framework-agnostic hooks** first. LangGraph and Agno do not need to be installed to use the SDK — copy the patterns below or run the demos.

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
| `wrap_retrieved_content` | After RAG / web fetch, before context insert |
| `before_tool_call` | Before every tool execution (always local, even in server mode) |
| `scan_agent_output` | Before returning response to user |
| `scan_request_isolated` | Eval / probes (no session taint bleed) |

## LangGraph

```python
from unplug import Guard
from unplug.integrations.langgraph import langgraph_input_node, langgraph_tool_guard
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard(mode="server"))  # hosted API
graph.add_node("unplug_gate", langgraph_input_node(hooks))

tool_guard = langgraph_tool_guard(hooks)
decision = tool_guard("shell_exec", {"command": "..."})
if not decision.allowed:
    ...
```

Demo (no `langgraph` package required):

```bash
python examples/langgraph_hooks_demo.py
```

## Agno

```python
from agno.agent import Agent
from unplug import Guard
from unplug.integrations.agno import agno_pre_run_hook, agno_post_run_hook, agno_tool_hook
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard())
agent = Agent(
    pre_hooks=[agno_pre_run_hook(hooks)],
    # wire post_run / tool middleware per Agno version
)
```

Demo:

```bash
python examples/agno_hooks_demo.py
```

## Hosted vs local

| Setup | Guard init |
|-------|------------|
| Your VM + API key | `Guard(mode="server")` + `UNPLUG_API_KEY` |
| Local sidecar | `Guard(mode="server", server_url="http://127.0.0.1:8000")` |
| Embedded ML | `Guard()` + `active_model=tiny` |

See [`DEPLOYMENT.md`](DEPLOYMENT.md).

## Docker E2E (sidecar + examples)

```bash
cd sdk
chmod +x scripts/docker_e2e.sh
./scripts/docker_e2e.sh
# or: make docker-e2e
```

Builds `unplug-server` sidecar, waits for `/v1/health`, runs `local_sidecar_client.py` and `hosted_client.py`.

## What is not included yet

- Official PyPI extras `unplug-ai[langgraph]` / `[agno]` (hooks work without them)
- Auto-instrumentation via `Guard.init()` (manual hooks only)
- MCP / CrewAI / LlamaIndex wrappers (same `AgentHooks` pattern applies)
