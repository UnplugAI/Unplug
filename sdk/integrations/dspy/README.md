# DSPy

**Extra:** `pip install "unplug-ai[dspy]"`  
**Module:** `unplug.integrations.dspy`

[DSPy](https://dspy.ai/) programs are `dspy.Module` subclasses with a `forward`
method; `dspy.ReAct` runs a tool-calling loop over plain callables. Unplug wires
into three points:

- **Input/output** — `unplug_guard_module` wraps any module so Unplug scans its
  string inputs before it runs and its `dspy.Prediction` answer after.
- **Tools** — `dspy_guard_tool` wraps a callable so a destructive call is blocked
  before it executes, preserving the signature DSPy needs for `dspy.ReAct`.
- **Manual guards** — `dspy_input_guard` / `dspy_output_guard` / `dspy_tool_guard`
  are plain callables for custom control flow inside a `forward`.

## Wrap a module

```python
import dspy
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.dspy import unplug_guard_module

hooks = AgentHooks(Guard())  # or Guard(mode="server")
program = dspy.ChainOfThought("question -> answer")
guarded = unplug_guard_module(program, hooks)

result = guarded(question="What is the capital of France?")  # scans input + answer
```

## Guard ReAct tools

```python
from unplug.integrations.dspy import dspy_guard_tool

def send_email(to: str, body: str) -> str:
    ...

react = dspy.ReAct("question -> answer", tools=[dspy_guard_tool(send_email, hooks)])
```

A blocked tool raises before it runs; DSPy records the error as an observation
and the destructive call never executes.

## Hook points

| DSPy stage | Unplug |
|------------|--------|
| Module input + output | `unplug_guard_module` |
| `dspy.ReAct(tools=[...])` | `dspy_guard_tool` |
| Manual input scan | `dspy_input_guard` |
| Manual output scan | `dspy_output_guard` |
| Manual tool gate | `dspy_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no dspy install required)

```bash
python examples/dspy_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
