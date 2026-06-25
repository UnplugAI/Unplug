# Semantic Kernel

**Extra:** `pip install "unplug-ai[semantic-kernel]"`  
**Module:** `unplug.integrations.semantic_kernel`

## Filters around kernel invoke

```python
from semantic_kernel import Kernel
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.semantic_kernel import (
    semantic_kernel_prompt_filter,
    semantic_kernel_function_filter,
    semantic_kernel_response_filter,
)

hooks = AgentHooks(Guard())
filter_prompt = semantic_kernel_prompt_filter(hooks)
guard_fn = semantic_kernel_function_filter(hooks)
filter_response = semantic_kernel_response_filter(hooks)

safe_prompt = filter_prompt(user_input)
decision = guard_fn("EmailPlugin.Send", {"to": addr, "body": body})
if not decision.allowed:
    raise RuntimeError(decision.message)
answer = filter_response(kernel_result)
```

Wire filters into SK's filter pipeline or call explicitly before/after `kernel.invoke`.

## Hook points

| SK stage | Unplug hook |
|----------|-------------|
| User prompt | `semantic_kernel_prompt_filter` |
| Plugin / function | `semantic_kernel_function_filter` |
| Kernel output | `semantic_kernel_response_filter` |
