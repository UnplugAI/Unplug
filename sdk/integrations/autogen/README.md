# Microsoft AutoGen

**Extra:** `pip install "unplug-ai[autogen]"`
**Module:** `unplug.integrations.autogen`

## Wire Unplug into AutoGen agents

```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.autogen import (
    autogen_user_message_hook,
    autogen_tool_hook,
    autogen_reply_hook,
)

hooks = AgentHooks(Guard())
filter_user = autogen_user_message_hook(hooks)
guard_tool = autogen_tool_hook(hooks)
filter_reply = autogen_reply_hook(hooks)

user_text = "Summarize the latest sales report"
message = {"role": "user", "content": user_text}
safe_message = filter_user(message)

cmd = "ls -la"
decision = guard_tool("run_shell", {"command": cmd})
if not decision.allowed:
    raise RuntimeError(decision.message)

agent_reply = "Here is the summary you asked for."
reply = filter_reply(agent_reply)
```

Register hooks in `ConversableAgent.register_hook` or call explicitly before `generate_reply` depending on your AutoGen version.

## Hook points

| AutoGen stage | Unplug hook |
|---------------|-------------|
| Inbound message | `autogen_user_message_hook` |
| Tool / function | `autogen_tool_hook` |
| Outbound reply | `autogen_reply_hook` |
