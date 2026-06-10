---
title: Unplug Tiny Demo
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: gradio
sdk_version: 5.9.1
app_file: app.py
python_version: 3.11
pinned: false
license: apache-2.0
suggested_hardware: cpu-basic
---

# unplug-tiny span injection demo

Interactive demo for **[Unplug-AI/unplug-tiny-v1](https://huggingface.co/Unplug-AI/unplug-tiny-v1)** — dual-head span detection with redaction.

**Disclaimer:** Preview OSS detector — not a production WAF. Known gaps: Deepset OOD recall, harmful-non-injection contrast FPR, WildGuard benign FPR.

## Features

- Scan arbitrary text with the unplug-tiny ML model (or regex-only baseline)
- Span highlights and redacted output
- Six curated examples (BIPIA TP, notinject TN, XSTest homonym, Deepset FN risk, jailbreak TP, harmful contrast FP risk)

## Agent integration

See [agent_exfil_demo.py](https://github.com/UnplugAI/Unplug/blob/main/sdk/examples/agent_exfil_demo.py) for hidden injection → tainted session → blocked exfil.

## Local run

```bash
cd sdk && uv sync --extra ml && uv pip install gradio
uv run python demo/unplug_tiny_demo.py
```
