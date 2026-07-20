"""Framework integration hooks for agent runtimes.

Unplug ships adapters for LangGraph, LangChain, OpenAI Agents SDK, CrewAI,
Haystack, and many others. Framework code lives in this package; **per-framework
wiring guides** live in the repository (not bundled in the PyPI wheel):

https://github.com/UnplugAI/Unplug/tree/dev/sdk/integrations

Quick links:

- All frameworks + extras: ``integrations/README.md``
- Custom ReAct / hand-rolled loop: ``integrations/custom-loop/README.md``
- Action semantics (REVIEW vs BLOCK): ``docs/AGENT_ACTIONS.md``
- 5-minute install → scan: ``docs/GETTING_STARTED.md``

Core types exported here: :class:`AgentHooks`, :class:`HookDecision`.
"""

from unplug.integrations.hooks import AgentHooks, HookDecision

__all__ = [
    "AgentHooks",
    "HookDecision",
]
