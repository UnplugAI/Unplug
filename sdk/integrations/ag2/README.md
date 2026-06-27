# AG2

**Extra:** `pip install "unplug-ai[ag2]"`  
**Module:** `unplug.integrations.ag2`

[AG2](https://docs.ag2.ai/) (the community fork of AutoGen, imported as `autogen`)
attaches hooks to a `ConversableAgent` via `register_hook`. Unplug wires into:

- **Incoming** — `process_last_received_message` scans the last received message
  for injection (redacts or raises).
- **Outgoing** — `process_message_before_send` scans a message before it is sent
  to another agent, catching leaked secrets / unsafe content.
- **Tools** — `ag2_guard_tool` wraps a callable so a destructive call is blocked
  before it runs; pair it with `register_function`.

> **Not the same as `autogen`.** The `autogen` extra targets Microsoft's
> `autogen-agentchat` (imported as `autogen_agentchat`). AG2 installs as the `ag2`
> package and imports as `autogen` — the two can coexist.

## Register the hooks

```python
from autogen import ConversableAgent
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.ag2 import register_unplug_hooks

hooks = AgentHooks(Guard())  # or Guard(mode="server")

agent = ConversableAgent(name="assistant", llm_config=llm_config)
register_unplug_hooks(agent, hooks)  # incoming + outgoing message guards
```

## Tool policy

```python
from autogen import register_function
from unplug.integrations.ag2 import ag2_guard_tool

register_function(
    ag2_guard_tool(run_sql, hooks),
    caller=assistant,
    executor=user_proxy,
    description="Run a read-only SQL query",
)
```

A blocked tool raises before it runs, so the destructive call never executes.

## Hook points

| AG2 stage | Unplug |
|-----------|--------|
| `process_last_received_message` | `ag2_received_message_hook` |
| `process_message_before_send` | `ag2_message_hook` |
| both, in one call | `register_unplug_hooks` |
| `register_function` | `ag2_guard_tool` |
| Manual tool gate | `ag2_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no ag2 install required)

```bash
python examples/ag2_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
