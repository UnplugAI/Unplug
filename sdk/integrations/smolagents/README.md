# smolagents

**Extra:** `pip install "unplug-ai[smolagents]"`
**Module:** `unplug.integrations.smolagents`

Hugging Face [smolagents](https://huggingface.co/docs/smolagents) runs code and
tool-calling agents. Unplug wires into three points:

- **Task gate** — scan the task string before `agent.run(task)`.
- **Final-answer check** — `final_answer_checks=[...]` validators run with the
  signature `(final_answer, memory, agent)` before an answer is accepted; Unplug
  raises on secret leaks / unsafe output.
- **Tool policy** — gate destructive/exfil tool calls locally.

## Wire Unplug into a CodeAgent

```python
from smolagents import CodeAgent, InferenceClientModel
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.smolagents import (
    smolagents_task_guard,
    smolagents_final_answer_check,
    smolagents_tool_guard,
)

hooks = AgentHooks(Guard())  # or Guard(mode="server")
guard_task = smolagents_task_guard(hooks)

agent = CodeAgent(
    tools=[],
    model=InferenceClientModel(),
    final_answer_checks=[smolagents_final_answer_check(hooks)],
)

agent.run(guard_task("Summarize the latest sales report"))
```

## Tool policy

```python
guard = smolagents_tool_guard(hooks)
decision = guard("python_interpreter", {"code": code})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| smolagents stage | Unplug |
|------------------|--------|
| Before `agent.run` | `smolagents_task_guard` |
| `final_answer_checks` | `smolagents_final_answer_check` |
| Before a tool | `smolagents_tool_guard` |

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

## Demo (no smolagents install required)

```bash
python examples/smolagents_hooks_demo.py
```

See also: [integrations/README.md](../README.md)
