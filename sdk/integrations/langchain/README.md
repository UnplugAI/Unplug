# LangChain

**Extra:** `pip install "unplug-ai[langchain]"`  
**Module:** `unplug.integrations.langchain`

> For **LangGraph** graphs, use the dedicated [`langgraph`](../langgraph/README.md)
> integration. This guide covers plain LangChain / LCEL chains.

LangChain callbacks are **observer-only** — they can watch a run but not change
or block the value flowing through a chain. So Unplug enforces in two places:

- **LCEL Runnables** wrap the head and tail of a chain to scan/redact input and
  output (and raise when blocked).
- A **callback handler** uses the one spot a callback *can* intervene — raising
  inside `on_tool_start` aborts a destructive tool before it executes.

## Guard an LCEL chain

```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.langchain import unplug_input_runnable, unplug_output_runnable

hooks = AgentHooks(Guard())  # or Guard(mode="server")

chain = unplug_input_runnable(hooks) | prompt | llm | unplug_output_runnable(hooks)
chain.invoke("user message")   # redacts in place; raises RuntimeError if blocked
```

The plain `str -> str` guards are also usable directly (e.g. inside your own
`RunnableLambda`):

```python
from unplug.integrations.langchain import langchain_input_guard, langchain_output_guard
```

## Block destructive tools via callback

```python
from unplug.integrations.langchain import unplug_callback_handler

handler = unplug_callback_handler(hooks)
agent_executor.invoke({"input": task}, config={"callbacks": [handler]})
# on_tool_start raises before a blocked tool (e.g. shell `rm -rf /`) runs
```

## Hook points

| Chain stage | Unplug |
|-------------|--------|
| Head of chain | `unplug_input_runnable` / `langchain_input_guard` |
| Tail of chain | `unplug_output_runnable` / `langchain_output_guard` |
| Before a tool | `unplug_callback_handler` (`on_tool_start`) / `langchain_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no LangChain install required)

```bash
python examples/langchain_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
