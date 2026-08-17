# Letta

**Extra:** `pip install "unplug-ai[letta]"`
**Module:** `unplug.integrations.letta`

[Letta](https://docs.letta.com/) (formerly MemGPT) runs persistent, stateful
agents behind a server; you talk to them with the `letta-client` SDK. Because the
agent runs server-side, Unplug guards the **client boundary**:

- **Input** — scan the user message before `client.agents.messages.create(...)`.
- **Output** — pull assistant text out of `response.messages` (entries with
  `message_type == "assistant_message"`) and scan it for leaks / unsafe content.
- **Tools** — gate client-side tool calls before they run.

## Guard the client boundary

```python
from letta_client import Letta
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.letta import letta_input_guard, scan_letta_response

client = Letta(environment="local")
hooks = AgentHooks(Guard())  # or Guard(mode="server")
guard_in = letta_input_guard(hooks)

response = client.agents.messages.create(
    agent_id=agent.id,
    messages=[{"role": "user", "content": guard_in(user_text)}],  # redacts or raises
)

decision = scan_letta_response(hooks, response)
if not decision.allowed:
    ...  # withhold the assistant message / surface a safe fallback
```

## Tool policy

```python
from unplug.integrations.letta import letta_tool_guard

decision = letta_tool_guard(hooks)("shell", {"command": cmd})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| Letta stage | Unplug |
|-------------|--------|
| Before `messages.create` | `letta_input_guard` |
| `response.messages` | `letta_extract_assistant_text` + `scan_letta_response` |
| Assistant text | `letta_output_guard` |
| Client-side tool | `letta_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no letta-client install required)

```bash
python examples/letta_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
