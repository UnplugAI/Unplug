---
title: README
emoji: 🔌
colorFrom: blue
colorTo: green
sdk: static
pinned: false
---

<p align="center">
  <b style="font-size: 1.6em">Unplug - pull the plug on bad AI</b>
</p>

**Runtime defense layer for LLM apps and agents.** Unplug detects, localizes, and **redacts** prompt injection at the span level - instead of binary-blocking entire documents.

Untrusted text is everywhere in an LLM pipeline: user messages, RAG chunks, tool output, fetched web pages. One hidden instruction in any of them can hijack your agent. Unplug scans all of it, cuts out the attack, and keeps the rest usable.

## What we ship

| | |
| --- | --- |
| **[`unplug-ai` SDK](https://github.com/UnplugAI/Unplug)** | Guard pipeline: normalization, regex + ML scanners, taint tracking, tool-call gates, streaming scan, span redaction. Apache-2.0. |
| **[unplug-tiny-v1](https://huggingface.co/Unplug-AI/unplug-tiny-v1)** | Dual-head span detector (70M params): doc classifier decides *whether*, BIOES token head localizes *where*. Honest per-axis benchmarks on the card. |
| **[Live demo](https://huggingface.co/spaces/Unplug-AI/unplug-tiny-demo)** | Paste text, see span highlights + redacted output, compare against a regex-only baseline. |

## Why span-level?

Binary classifiers force a bad trade: block the whole document (lose the data) or allow it (eat the attack). Unplug's token head localizes the injected instruction to character offsets, so the pipeline redacts just that span - the rest of the document flows through.

## Get started

```bash
pip install "unplug-ai[ml]"
```

```python
from unplug import Guard

guard = Guard.with_tiny()              # auto-downloads unplug-tiny-v1
result = guard.scan(untrusted_text)
if not result.safe:
    use(result.redacted_text)          # attack removed, content preserved
```

Agent kill-chain walkthrough: [hidden webpage injection -> tainted session -> blocked exfil tool call](https://github.com/UnplugAI/Unplug/blob/main/sdk/examples/agent_exfil_demo.py).

## Principles

- **Nothing enters as a raw string** - all text carries provenance and trust level.
- **Fail closed** - scanner errors block, never silently allow.
- **Honest numbers** - every published metric comes from a frozen eval harness on held-out data, including the axes we fail.
