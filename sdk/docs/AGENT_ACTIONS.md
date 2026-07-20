# Agent actions: ALLOW, REDACT, REVIEW, BLOCK

Every Unplug scan returns an **`Action`**. Agent hosts and integration adapters must handle each action differently — especially **`REVIEW`**, which is not the same as **`BLOCK`**.

Examples below use `from unplug import Guard` for the host and `from unplug.api.*` only
where wire types or enums are needed. Do not import from `unplug.core.*`.

## Decision table

| `result.action` | `result.safe` | `HookDecision.allowed` | Agent host should |
|-----------------|---------------|------------------------|-------------------|
| `allow` | `True` | `True` | Proceed with original text |
| `redact` | varies | usually `True` | Use `result.redacted_text` (or `decision.redacted_text`) |
| `review` | `False` | `False` | **Pause** — request human approval before side-effect tools; do not treat as silent allow |
| `block` | `False` | `False` | **Stop** — do not call the LLM or execute the tool |
| `abstain` | `False` | `False` | Escalate (judge, secondary model, or operator) |

`HookDecision.allowed` is `False` for both **`review`** and **`block`**. Check `decision.result.action` (or `decision.needs_review`) to tell them apart.

## Typical triggers

| Situation | Action |
|-----------|--------|
| Direct prompt injection in user input | `block` |
| Secret leak in model output | `block` or `redact` |
| Destructive shell/SQL tool | `block` |
| Side-effect tool after untrusted fetch (tainted session) | `review` |
| Large wire transfer | `block` or `review` |

After a web fetch or RAG ingest, call `guard.notify_taint_source("web_fetch")` so the next side-effect tool (email, upload, payment) returns **`review`** instead of **`allow`**.

## REVIEW + human approval

`Guard` accepts an **`ApprovalProvider`**. When a tool call returns `review`, Unplug builds an `ApprovalRequest` and calls your provider. If it returns `True`, the tool call is re-evaluated and may proceed.

```python
from unplug import Guard
from unplug.api.types import ApprovalRequest
from unplug.integrations.hooks import AgentHooks


class CliApprovalProvider:
    """Example: prompt an operator in the terminal."""

    def request_approval(self, request: ApprovalRequest) -> bool:
        print(f"\n[UNPLUG REVIEW] Tool: {request.tool_name}")
        print(f"  Reason: {request.reason}")
        print(f"  Args: {request.arguments}")
        answer = input("Approve this tool call? [y/N] ").strip().lower()
        return answer in {"y", "yes"}


guard = Guard(approval=CliApprovalProvider())
hooks = AgentHooks(guard)

# Simulate tainted session (e.g. after fetching untrusted web content)
guard.notify_taint_source("web_fetch")

decision = hooks.before_tool_call("send_email", {"to": "user@example.com", "body": "summary"})
if decision.needs_review:
    # ApprovalProvider already ran inside check_tool_call; if still not allowed, hold.
    print("Held for review:", decision.message)
elif not decision.allowed:
    raise RuntimeError(decision.message)  # hard block
else:
    execute_send_email(...)
```

For batch/cron agents, **never** auto-approve: use a provider that returns `False` unless an operator explicitly signed off (see [`HERMES_AGENT_SECURITY.md`](HERMES_AGENT_SECURITY.md)).

## Integration adapter pattern

Replace bare `raise RuntimeError` on every `not decision.allowed` with action-aware handling:

```python
from unplug.api.enums import Action

decision = hooks.before_tool_call(tool_name, tool_args)
if decision.result.action == Action.REVIEW:
    return hold_for_operator(decision)  # pause workflow
if not decision.allowed:
    raise RuntimeError(decision.message)  # block
# allowed or redacted — proceed
```

LangChain note: **`on_tool_start` callbacks are observer-only** for input/output. Use **`unplug_input_runnable` / `unplug_output_runnable`** for enforcement, plus the callback (or direct `before_tool_call`) for tools.

## Context files (AGENTS.md)

`scan_context_file` returns **`(text_for_prompt, scan_result)`** — not a single result:

```python
text_for_prompt, result = guard.scan_context_file(raw_agents_md, filename="AGENTS.md")
if not result.safe:
    # text_for_prompt is already a blocked placeholder — do not load raw content
    load_system_prompt(text_for_prompt)
else:
    load_system_prompt(text_for_prompt)  # same as raw when clean
```

## Agent host checklist (full flow)

1. `scan_context_file` on AGENTS.md / rules before system prompt
2. `scan_user_input` on each user turn
3. `wrap_retrieved_content` on RAG / tool results entering context
4. `notify_taint_source` after fetch/read tools
5. `before_tool_call` before every side-effect tool (handle **review**)
6. `scan_agent_output` before returning to user
7. `reset_session_taint` between users / tenants

See also: [`README.md`](../README.md#protect-an-agent), [`integrations/custom-loop/README.md`](../integrations/custom-loop/README.md).
