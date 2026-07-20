# Custom agent loop

No extra install required — use `AgentHooks` directly in any ReAct, while-loop, or hand-rolled orchestrator.

See [`docs/AGENT_ACTIONS.md`](../docs/AGENT_ACTIONS.md) for **REVIEW** vs **BLOCK** and human approval.

## Minimal ReAct loop

```python
from unplug import Guard
from unplug.api.enums import Action
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard())

def run_turn(user_message: str) -> str:
    in_decision = hooks.scan_user_input(user_message)
    if not in_decision.allowed:
        raise RuntimeError(in_decision.message)

    # ... call LLM ...

    for tool_name, tool_args in planned_tools:
        tool_decision = hooks.before_tool_call(tool_name, tool_args)
        if tool_decision.needs_review:
            # Tainted session + side-effect tool — pause for operator (ApprovalProvider)
            raise RuntimeError(tool_decision.message or "Tool held for review")
        if not tool_decision.allowed:
            raise RuntimeError(tool_decision.message)
        result = execute(tool_name, tool_args)
        context, _ = hooks.wrap_retrieved_content(result)

    out_decision = hooks.scan_agent_output(model_text)
    if not out_decision.allowed:
        raise RuntimeError(out_decision.message)
    return out_decision.result.redacted_text or model_text
```

## Eval / benchmark isolation

```python
result = hooks.scan_request_isolated(probe_text)  # no session taint bleed
```

## Session taint

After fetching untrusted web content:

```python
hooks.guard.notify_taint_source("web_fetch")
# subsequent side-effect tools return review until session reset
hooks.reset_session()  # clear between users / tenants
```

## Hosted API

```python
hooks = AgentHooks(Guard(mode="server", server_api_key=os.environ["UNPLUG_API_KEY"]))
```

Input/output scans hit the API; **tool policy always runs locally**.
