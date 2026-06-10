"""Hugging Face Space entrypoint (Gradio expects app.py at repo root)."""

from __future__ import annotations

from unplug_tiny_demo import build_demo

demo = build_demo()

if __name__ == "__main__":
    demo.launch()
