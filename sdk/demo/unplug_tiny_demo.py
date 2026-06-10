"""Gradio demo for unplug-tiny span detection and redaction."""

from __future__ import annotations

import html
import json
import threading
from pathlib import Path
from typing import Any

import gradio as gr

from unplug import Guard
from unplug.api.types import Finding, ScanResult
from unplug.config.guard import GuardConfig

DEMO_DIR = Path(__file__).resolve().parent
EXAMPLES_PATH = DEMO_DIR / "examples.json"
DISCLAIMER = (
    "**Preview OSS detector — not a production WAF.** "
    "Known gaps: Deepset OOD recall, harmful-non-injection contrast FPR, WildGuard benign FPR."
)

_guard_ml: Guard | None = None
_guard_regex: Guard | None = None
_guard_lock = threading.Lock()


def load_examples() -> dict[str, dict[str, str]]:
    with EXAMPLES_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _get_guard(*, use_ml: bool) -> Guard:
    global _guard_ml, _guard_regex
    with _guard_lock:
        if use_ml:
            if _guard_ml is None:
                _guard_ml = Guard.with_tiny(auto_download=True, require_ml=True)
            return _guard_ml
        if _guard_regex is None:
            _guard_regex = Guard(
                scanners=["injection"],
                config=GuardConfig(active_model=None, auto_download_model=False),
            )
        return _guard_regex


def highlight_spans(text: str, findings: list[Finding]) -> str:
    if not text:
        return "<p><em>(empty)</em></p>"
    if not findings:
        return f'<pre style="white-space:pre-wrap">{html.escape(text)}</pre>'

    spans = sorted(findings, key=lambda f: (f.span_start, f.span_end))
    parts: list[str] = []
    pos = 0
    for finding in spans:
        if finding.span_end <= pos:
            continue
        start = max(finding.span_start, pos)
        if start > pos:
            parts.append(html.escape(text[pos:start]))
        end = min(finding.span_end, len(text))
        snippet = html.escape(text[start:end])
        bg = "#f8d7da" if finding.subcategory == "doc_head" else "#fff3cd"
        title = html.escape(f"{finding.category}/{finding.subcategory} ({finding.score:.2f})")
        parts.append(f'<mark style="background:{bg}" title="{title}">{snippet}</mark>')
        pos = end
    if pos < len(text):
        parts.append(html.escape(text[pos:]))
    return f'<pre style="white-space:pre-wrap">{"".join(parts)}</pre>'


def findings_rows(result: ScanResult) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for finding in result.findings:
        rows.append(
            [
                finding.category,
                finding.subcategory,
                finding.span_start,
                finding.span_end,
                round(finding.score, 3),
                finding.evidence[:120],
            ]
        )
    return rows


def verdict_markdown(result: ScanResult, expected: str | None) -> str:
    lines = [
        f"- **safe:** `{result.safe}`",
        f"- **action:** `{result.action.value}`",
        f"- **risk_score:** `{result.risk_score:.3f}`",
        f"- **latency_ms:** `{result.latency_ms:.1f}`",
        f"- **findings:** `{len(result.findings)}`",
    ]
    if expected:
        actual = "safe" if result.safe else "block"
        match = actual == expected
        status = "match" if match else "mismatch"
        lines.append(f"- **expected:** `{expected}` → **actual:** `{actual}` ({status})")
    return "\n".join(lines)


def scan_text(
    text: str,
    use_ml: bool,
    example_key: str | None,
) -> tuple[str, str, str, list[list[Any]], str]:
    if not text.strip():
        return DISCLAIMER, "", "<p><em>Enter text to scan.</em></p>", [], ""

    examples = load_examples()
    expected = None
    note = ""
    if example_key and example_key in examples:
        expected = examples[example_key]["expected"]
        note = examples[example_key]["note"]

    guard = _get_guard(use_ml=use_ml)
    result = guard.scan(text, source="user")

    highlighted = highlight_spans(text, result.findings)
    redacted = result.redacted_text if result.redacted_text is not None else text
    verdict = verdict_markdown(result, expected)
    if note:
        verdict = f"{verdict}\n\n**Example note:** {note}"

    mode_label = "ML (unplug-tiny)" if use_ml else "regex only"
    header = f"{DISCLAIMER}\n\n**Mode:** {mode_label}"

    return header, verdict, highlighted, findings_rows(result), redacted


def build_demo() -> gr.Blocks:
    examples = load_examples()
    choices = [(meta["label"], key) for key, meta in examples.items()]

    with gr.Blocks(title="Unplug Tiny Demo") as demo:
        gr.Markdown(
            "# Unplug Tiny — span injection demo\n\n"
            "Scan text with the dual-head **unplug-tiny-v1** model (`Unplug-AI/unplug-tiny-v1`). "
            "Spans are highlighted; risky regions are redacted in the output panel.\n\n"
            f"{DISCLAIMER}"
        )

        with gr.Row():
            example_dd = gr.Dropdown(
                choices=choices,
                label="Curated examples",
                value=None,
            )
            use_ml = gr.Checkbox(value=True, label="Use ML model (uncheck for regex only)")

        text_in = gr.Textbox(
            label="Input text",
            lines=10,
            placeholder="Paste user message, RAG chunk, or tool output…",
        )

        with gr.Row():
            gr.ClearButton([text_in], value="Clear")
            scan_btn = gr.Button("Scan", variant="primary")

        gr.Markdown("### Results")
        disclaimer_out = gr.Markdown()
        verdict_out = gr.Markdown(label="Verdict")
        with gr.Row():
            highlight_out = gr.HTML(label="Span highlights")
            redacted_out = gr.Textbox(label="Redacted text", lines=10)
        findings_out = gr.Dataframe(
            headers=["category", "subcategory", "start", "end", "score", "evidence"],
            label="Findings",
            interactive=False,
        )

        exfil_url = (
            "https://github.com/UnplugAI/Unplug/blob/main/sdk/examples/agent_exfil_demo.py"
        )
        gr.Markdown(
            "### Agent integration\n\n"
            "For hidden webpage injection → tainted session → blocked exfil, "
            f"see [`agent_exfil_demo.py`]({exfil_url})."
        )

        def load_example(key: str | None) -> str:
            if not key:
                return ""
            return examples[key]["text"]

        example_dd.change(load_example, inputs=example_dd, outputs=text_in)

        scan_btn.click(
            scan_text,
            inputs=[text_in, use_ml, example_dd],
            outputs=[disclaimer_out, verdict_out, highlight_out, findings_out, redacted_out],
        )

    return demo


def main() -> None:
    build_demo().launch()


if __name__ == "__main__":
    main()
