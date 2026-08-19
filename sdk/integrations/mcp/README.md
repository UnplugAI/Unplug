# MCP (Model Context Protocol)

**Extra:** `pip install "unplug-ai[mcp]"` for client-side MCP tooling tests.
**Server:** use the standalone [`unplug-mcp`](https://github.com/UnplugAI/unplug-mcp) package for Claude Code / Cursor.

## Hosted MCP server (recommended)

Add to Claude Desktop / Cursor / Windsurf config:

```json
{
  "mcpServers": {
    "unplug": {
      "command": "uvx",
      "args": ["unplug-mcp"],
      "env": {
        "UNPLUG_MODE": "local"
      }
    }
  }
}
```

For hosted scans:

```json
"env": {
  "UNPLUG_MODE": "server",
  "UNPLUG_SERVER_URL": "https://api.unplug-ai.org/v1",
  "UNPLUG_API_KEY": "sk-..."
}
```

## SDK hooks for custom MCP hosts

If you build your own MCP host, treat **tool results as untrusted**:

<!-- doc-drift: skip-exec: fragment meant to live inside your own tool-result handler -->
```python
from unplug import Guard
from unplug.integrations.hooks import AgentHooks

hooks = AgentHooks(Guard())
wrapped, decision = hooks.wrap_retrieved_content(tool_result_text)
if not decision.allowed:
    return error_to_model(wrapped)
```

Scan **tool arguments** before execution with `hooks.before_tool_call`.

## Related

- [unplug-mcp README](https://github.com/UnplugAI/unplug-mcp)
- [integrations/custom-loop](../custom-loop/README.md) for non-MCP agents
