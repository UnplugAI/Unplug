# Griptape

**Extra:** `pip install "unplug-ai[griptape]"`  
**Module:** `unplug.integrations.griptape`

[Griptape](https://griptape.ai/) structures (Agent, Pipeline, Workflow) run Tasks.
Every Task exposes `on_before_run` / `on_after_run` lifecycle hooks, and Tools are
`BaseTool` classes with `@activity` methods. Unplug wires into three points:

- **Input** — `unplug_before_run` scans `task.input.value` before the task runs
  (redacts in place or raises) — the documented pattern for masking task input.
- **Output** — `unplug_after_run` scans `task.output.value` after the task runs.
- **Tools** — `griptape_tool_guard` gates a tool activity before it executes.

## Wire Unplug into a task

```python
from griptape.structures import Agent
from griptape.tasks import PromptTask
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.griptape import unplug_before_run, unplug_after_run

hooks = AgentHooks(Guard())  # or Guard(mode="server")

agent = Agent(
    tasks=[
        PromptTask(
            "Respond to this user: {{ args[0] }}",
            on_before_run=unplug_before_run(hooks),
            on_after_run=unplug_after_run(hooks),
        )
    ]
)
agent.run("Summarize the latest sales report")
```

`unplug_before_run` raises on a blocked input and otherwise rewrites
`task.input` with the redacted text; `unplug_after_run` does the same for
`task.output.value`.

## Tool policy

```python
from unplug.integrations.griptape import griptape_tool_guard

decision = griptape_tool_guard(hooks)("FileManager", {"path": path})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| Griptape stage | Unplug |
|----------------|--------|
| `on_before_run` | `unplug_before_run` |
| `on_after_run` | `unplug_after_run` |
| Before a tool activity | `griptape_tool_guard` |
| Manual input scan | `griptape_input_guard` |
| Manual output scan | `griptape_output_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no griptape install required)

```bash
python examples/griptape_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
