# Atomic Agents

**Extra:** `pip install "unplug-ai[atomic-agents]"`  
**Module:** `unplug.integrations.atomic_agents`

[Atomic Agents](https://brainblend-ai.github.io/atomic-agents/) (v2) is a
Pydantic-schema-driven framework: `AtomicAgent[InputSchema, OutputSchema]` with
`agent.run(input_schema) -> output_schema`, where schemas subclass `BaseIOSchema`
(default text field `chat_message`). Unplug wires into three points:

- **Input** — scan the input schema's text field before `agent.run` (redact or raise).
- **Output** — scan the output schema's text field after `agent.run`.
- **Tools** — gate a `BaseTool` call before it executes.

> Atomic Agents 2.x requires Python ≥3.12, so this extra is a no-op on 3.11.

## Guard agent I/O

```python
from atomic_agents import AtomicAgent, BasicChatInputSchema, BasicChatOutputSchema
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.atomic_agents import atomic_input_guard, atomic_scan_output

hooks = AgentHooks(Guard())  # or Guard(mode="server")
guard_in = atomic_input_guard(hooks)

safe_input = guard_in(BasicChatInputSchema(chat_message=user_text))  # redacts or raises
response = agent.run(safe_input)
atomic_scan_output(hooks, response)  # raises on leak / unsafe output
```

Use a custom field name when your schema's text lives elsewhere:
`atomic_input_guard(hooks, field="query")`.

## Tool policy

```python
from unplug.integrations.atomic_agents import atomic_tool_guard

decision = atomic_tool_guard(hooks)("SearchTool", {"query": query})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| Atomic Agents stage | Unplug |
|---------------------|--------|
| Before `agent.run` | `atomic_input_guard` / `atomic_scan_input` |
| After `agent.run` | `atomic_output_guard` / `atomic_scan_output` |
| Extract schema text | `atomic_extract_text` |
| Before a `BaseTool` | `atomic_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no atomic-agents install required)

```bash
python examples/atomic_agents_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
