# LangGraph

**Extra:** `pip install "unplug-ai[langgraph]"`
**Module:** `unplug.integrations.langgraph`

## Wire Unplug into a graph

```python
from langgraph.graph import StateGraph
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.langgraph import langgraph_input_node, langgraph_tool_guard

hooks = AgentHooks(Guard(mode="server"))  # or Guard() for local

graph = StateGraph(dict)
graph.add_node("unplug_gate", langgraph_input_node(hooks))
graph.add_node("agent", agent_node)

tool_guard = langgraph_tool_guard(hooks)

def run_tool(name: str, args: dict):
    decision = tool_guard(name, args)
    if not decision.allowed:
        raise RuntimeError(decision.message)
    return execute_tool(name, args)
```

## Hook points

| Graph stage | Unplug hook |
|-------------|-------------|
| Before agent node | `langgraph_input_node` |
| Before tool node | `langgraph_tool_guard` |
| After RAG fetch | `hooks.wrap_retrieved_content` |
| Before END | `hooks.scan_agent_output` |

## Demo (no LangGraph install)

```bash
python examples/langgraph_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
