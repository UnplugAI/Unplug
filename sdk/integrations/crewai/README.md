# CrewAI

**Extra:** `pip install "unplug-ai[crewai]"`
**Module:** `unplug.integrations.crewai`

## Wire Unplug into a Crew

```python
from crewai import Agent, Crew, Task
from unplug import Guard
from unplug.integrations.hooks import AgentHooks
from unplug.integrations.crewai import (
    crewai_task_input_guard,
    crewai_tool_guard,
    crewai_output_guard,
)

hooks = AgentHooks(Guard())
guard_input = crewai_task_input_guard(hooks)
guard_tool = crewai_tool_guard(hooks)
guard_output = crewai_output_guard(hooks)

inputs = {"topic": "Quarterly report summary"}
guard_input(inputs["topic"])

crew = Crew(agents=[...], tasks=[...])
result = crew.kickoff(inputs=inputs)
safe = guard_output(str(result))
```

## Hook points

| CrewAI stage | Unplug hook |
|--------------|-------------|
| Before kickoff | `crewai_task_input_guard` |
| Before tool | `crewai_tool_guard` |
| After kickoff | `crewai_output_guard` |

Tool enforcement runs **locally** even when input/output scans use `Guard(mode="server")`.
