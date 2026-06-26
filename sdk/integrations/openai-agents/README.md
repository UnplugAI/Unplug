# OpenAI Agents SDK

**Extra:** `pip install "unplug-ai[openai-agents]"`  
**Module:** `unplug.integrations.openai_agents`

The [OpenAI Agents SDK](https://openai.github.io/openai-agents-python/) has a
native **guardrails** system. Unplug plugs in as both an input and an output
guardrail: when a turn is blocked, the guardrail's tripwire fires and the SDK
raises `InputGuardrailTripwireTriggered` / `OutputGuardrailTripwireTriggered`,
halting the run before the model (or the user) ever sees the unsafe content.

## Wire Unplug into an Agent

```python
from agents import Agent, Runner
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.openai_agents import (
    openai_agents_input_guardrail,
    openai_agents_output_guardrail,
    openai_agents_tool_guard,
)

hooks = AgentHooks(Guard())  # or Guard(mode="server") for the hosted API

agent = Agent(
    name="Assistant",
    instructions="You are a helpful assistant.",
    input_guardrails=[openai_agents_input_guardrail(hooks)],
    output_guardrails=[openai_agents_output_guardrail(hooks)],
)

result = await Runner.run(agent, "Summarize the quarterly report.")
```

## Tool policy (always local)

Guardrails cover the input/output turns; tool authorization is enforced locally
and never delegated to the model. Gate the body of any function tool:

```python
guard = openai_agents_tool_guard(hooks)

@function_tool
def run_shell(command: str) -> str:
    decision = guard("run_shell", {"command": command})
    if not decision.allowed:
        raise RuntimeError(decision.message)
    return _execute(command)
```

## Hook points

| SDK stage | Unplug |
|-----------|--------|
| `input_guardrails` | `openai_agents_input_guardrail` |
| `output_guardrails` | `openai_agents_output_guardrail` |
| Inside a function tool | `openai_agents_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

Tool calls still use the local `openai_agents_tool_guard` even in server mode.

## Demo (no SDK install required)

```bash
python examples/openai_agents_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
