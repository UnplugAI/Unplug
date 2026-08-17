# Agno

**Extra:** `pip install "unplug-ai[agno]"`
**Module:** `unplug.integrations.agno`

## Wire Unplug into Agno Agent

```python
from agno.agent import Agent
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.agno import agno_pre_run_hook, agno_post_run_hook, agno_tool_hook

hooks = AgentHooks(Guard())
tool_guard = agno_tool_hook(hooks)

agent = Agent(
    pre_hooks=[agno_pre_run_hook(hooks)],
    # post_run: wrap response with agno_post_run_hook(hooks) per your Agno version
)

# Before executing a tool:
decision = tool_guard("send_email", {"to": "...", "body": "..."})
if not decision.allowed:
    raise RuntimeError(decision.message)
```

## Hook points

| Agno lifecycle | Unplug hook |
|----------------|-------------|
| Pre-run | `agno_pre_run_hook` |
| Tool call | `agno_tool_hook` |
| Post-run | `agno_post_run_hook` |

## Demo (no Agno install)

```bash
python examples/agno_hooks_demo.py
```
