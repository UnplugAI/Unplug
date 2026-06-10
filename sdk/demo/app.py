"""Hugging Face Space entrypoint (Gradio expects app.py at repo root)."""

from __future__ import annotations

import threading

from unplug_tiny_demo import build_demo, warm_start

# Download weights + load the model while the Space boots, not on first scan.
threading.Thread(target=warm_start, daemon=True).start()

demo = build_demo()

if __name__ == "__main__":
    demo.launch()
