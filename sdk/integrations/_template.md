# Integration guide template

Use this template when adding a new agent framework integration.

## Overview

- **Framework:**
- **PyPI extra:** `pip install "unplug-ai[<extra>]"`
- **Module:** `unplug.integrations.<module>`

## Threat model

Which hook points does this framework need?

- [ ] User input (pre-LLM)
- [ ] Retrieved / RAG content
- [ ] Tool / function calls
- [ ] Agent output (post-LLM)

## Installation

```bash
pip install "unplug-ai[<extra>]"
```

## Wiring

```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.<module> import ...

hooks = AgentHooks(Guard())
# wire hooks here
```

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key="sk-..."))
```

Tool calls must still use local `before_tool_call` even in server mode.

Handle **REVIEW** (tainted session) separately from **BLOCK** — see [`docs/AGENT_ACTIONS.md`](../../docs/AGENT_ACTIONS.md).

## Tests

Add cases to `tests/security/test_agent_integration_matrix.py`.

## Checklist

- [ ] No hard import of the framework at module load time
- [ ] Optional extra declared in `pyproject.toml`
- [ ] Guide added under `integrations/<name>/README.md`
- [ ] Demo or example script (optional)
- [ ] Matrix test cases added
