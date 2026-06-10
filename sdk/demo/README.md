---
title: Unplug Tiny
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: gradio
sdk_version: 5.9.1
app_file: app.py
python_version: 3.11
pinned: false
license: apache-2.0
short_description: Detect and redact prompt injection with span precision
models:
  - Unplug-AI/unplug-tiny-v1
---

# Unplug Tiny — prompt injection span demo

Interactive demo for **[Unplug-AI/unplug-tiny-v1](https://huggingface.co/Unplug-AI/unplug-tiny-v1)** — find the attack, cut the attack, keep the rest.

- Scan untrusted text with the dual-head span model (or a regex-only baseline)
- Span highlights, redacted output, per-finding scores
- Curated test cases — **including the ones this model gets wrong**

**Disclaimer:** Preview OSS detector — not a production WAF. Honest per-axis benchmarks (with failing gates) are on the [model card](https://huggingface.co/Unplug-AI/unplug-tiny-v1).

## Agent integration

Full kill chain (hidden webpage injection → tainted session → blocked exfil tool call): [agent_exfil_demo.py](https://github.com/UnplugAI/Unplug/blob/main/sdk/examples/agent_exfil_demo.py)

## Run locally

```bash
git clone https://github.com/UnplugAI/Unplug.git && cd Unplug/sdk
uv sync --extra ml && uv pip install gradio
uv run python demo/unplug_tiny_demo.py
```
