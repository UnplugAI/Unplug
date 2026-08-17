# Strands Agents

**Extra:** `pip install "unplug-ai[strands]"`
**Module:** `unplug.integrations.strands`

[Strands Agents](https://strandsagents.com/) (AWS) exposes a strongly-typed
hooks system. Unplug ships a `HookProvider` that subscribes to the before-tool
event and **cancels** a destructive/exfil tool call before it runs — the
documented way to gate tools. Input/output text guards cover the turn boundary.

## Wire the hook provider into an Agent

```python
from strands import Agent
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.strands import UnplugHookProvider

hooks = AgentHooks(Guard())  # or Guard(mode="server")

agent = Agent(
    model=model,
    tools=[...],
    hooks=[UnplugHookProvider(hooks)],
)
```

When the agent tries to call a blocked tool, the provider sets
`event.cancel_tool` with the block reason and the tool never executes. The event
class was renamed from `BeforeToolInvocationEvent` to `BeforeToolCallEvent`
across releases — the provider resolves whichever your version exposes.

## Manual guards

```python
from unplug.integrations.strands import strands_input_guard, strands_tool_guard

safe_prompt = strands_input_guard(hooks)(user_prompt)   # redacts or raises
decision = strands_tool_guard(hooks)("shell", {"command": cmd})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| Strands stage | Unplug |
|---------------|--------|
| `BeforeToolCallEvent` | `UnplugHookProvider` (sets `event.cancel_tool`) |
| Before `agent(prompt)` | `strands_input_guard` |
| Final text | `strands_output_guard` |
| Manual tool gate | `strands_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no strands install required)

```bash
python examples/strands_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
