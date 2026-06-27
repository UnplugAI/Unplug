# Google ADK

**Extra:** `pip install "unplug-ai[google-adk]"`  
**Module:** `unplug.integrations.google_adk`

Google's [Agent Development Kit](https://google.github.io/adk-docs/) exposes
guardrail callbacks that short-circuit a step by **returning an object**. Unplug
wires into two of them:

- `before_model_callback` returns an `LlmResponse` to **skip the LLM call** when
  the user input is blocked (input guardrail).
- `before_tool_callback` returns a result `dict` to **skip a destructive tool**
  and hand a blocked-result back to the model (tool policy).

> ADK passes callback arguments **by keyword**, so the callbacks keep the exact
> parameter names ADK requires (`callback_context`, `llm_request`, `tool`,
> `args`, `tool_context`).

## Wire Unplug into an LlmAgent

```python
from google.adk.agents import LlmAgent
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.google_adk import (
    unplug_before_model_callback,
    unplug_before_tool_callback,
)

hooks = AgentHooks(Guard())  # or Guard(mode="server")

agent = LlmAgent(
    name="assistant",
    model="gemini-2.0-flash",
    instruction="You are a helpful assistant.",
    before_model_callback=unplug_before_model_callback(hooks),
    before_tool_callback=unplug_before_tool_callback(hooks),
)
```

## Hook points

| ADK callback | Unplug | Blocks by returning |
|--------------|--------|---------------------|
| `before_model_callback` | `unplug_before_model_callback` | an `LlmResponse` (LLM call skipped) |
| `before_tool_callback` | `unplug_before_tool_callback` | a result `dict` (tool skipped) |

The request parser `adk_extract_user_text(llm_request)` and the tool callback are
plain/duck-typed, so you can unit-test them without ADK installed.

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

Tool policy is always enforced locally, even in server mode.

## Demo (no ADK install required)

```bash
python examples/google_adk_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
