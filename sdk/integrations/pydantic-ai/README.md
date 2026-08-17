# Pydantic AI

**Extra:** `pip install "unplug-ai[pydantic-ai]"`
**Module:** `unplug.integrations.pydantic_ai`

## Validators around Agent.run

```python
from pydantic_ai import Agent
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.pydantic_ai import (
    pydantic_ai_input_validator,
    pydantic_ai_tool_guard,
    pydantic_ai_output_validator,
)

hooks = AgentHooks(Guard())
validate_in = pydantic_ai_input_validator(hooks)
validate_out = pydantic_ai_output_validator(hooks)
guard_tool = pydantic_ai_tool_guard(hooks)

prompt = validate_in(user_prompt)
# wrap tool functions: call guard_tool(name, args) before execution
result = agent.run_sync(prompt)
text = validate_out(str(result.data))
```

## Hook points

| Pydantic AI stage | Unplug hook |
|-------------------|-------------|
| User prompt | `pydantic_ai_input_validator` |
| Tool call | `pydantic_ai_tool_guard` |
| Model output | `pydantic_ai_output_validator` |
