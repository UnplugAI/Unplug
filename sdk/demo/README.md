# unplug-tiny Gradio demo

Interactive span detection demo for **Unplug-AI/unplug-tiny-v1**.

## Run locally

```bash
cd sdk
uv sync --extra ml
uv pip install gradio
uv run python demo/unplug_tiny_demo.py
```

First scan downloads weights from Hugging Face (~90MB).

## Deploy to Hugging Face Spaces

Target: **Unplug-AI/unplug-tiny-demo** (Gradio, `cpu-basic`).

Copy `demo/app.py`, `demo/unplug_tiny_demo.py`, `demo/examples.json`, and `demo/requirements.txt` to the Space repo root, then push.

## Disclaimer

Preview OSS detector — not a production WAF. Known limitations are documented on the [model card](https://huggingface.co/Unplug-AI/unplug-tiny-v1).

## Agent integration

See [`examples/agent_exfil_demo.py`](../examples/agent_exfil_demo.py) for hidden injection → tainted session → blocked exfil.
