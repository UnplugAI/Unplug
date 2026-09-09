"""Gradio demo for unplug-tiny span detection and redaction."""

from __future__ import annotations

import contextlib
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

MODEL_URL = "https://huggingface.co/Unplug-AI/unplug-tiny-v1"
GITHUB_URL = "https://github.com/UnplugAI/Unplug"
EXFIL_URL = "https://github.com/UnplugAI/Unplug/blob/main/sdk/examples/agent_exfil_demo.py"

DISCLAIMER = (
    "Preview OSS detector - not a production WAF. Roadmap items (e.g. harmful-but-not-injection "
    "disposition) are labeled separately below. Regex baseline uses sensitive-context dual mode "
    "when tokens/secrets appear in text."
)

# Findings whose span covers nearly the whole input are document-level flags,
# not localized spans: surfaced in the verdict banner instead of painting everything.
_DOC_LEVEL_COVERAGE = 0.9
_DOC_LEVEL_MIN_CHARS = 120

COLOR_MAP = {
    "injection": "#f59e0b",
    "destructive": "#ef4444",
    "leakage": "#a855f7",
    "harmful": "#f43f5e",
    "limits": "#94a3b8",
}

CSS = """
.hero {text-align:center; padding: 8px 0 2px 0;}
.hero h1 {margin-bottom: 2px;}
.hero .tagline {font-size: 1.05rem; opacity: .85; margin: 2px 0 6px 0;}
.hero .links {font-size: .9rem; opacity: .8;}
.hero .disclaimer {font-size: .8rem; opacity: .6; margin-top: 6px;}
.verdict {padding: 14px 18px; border-radius: 10px; font-weight: 600; font-size: 1.02rem;
          line-height: 1.5;}
.verdict small {font-weight: 400; opacity: .8;}
.verdict-safe {background: rgba(34,197,94,.12); border: 1px solid rgba(34,197,94,.5);}
.verdict-block {background: rgba(239,68,68,.12); border: 1px solid rgba(239,68,68,.5);}
.verdict-review {background: rgba(245,158,11,.12); border: 1px solid rgba(245,158,11,.5);}
.verdict-idle {background: rgba(148,163,184,.1); border: 1px dashed rgba(148,163,184,.5);
               font-weight: 400; opacity: .8;}
.footer {text-align:center; font-size: .82rem; opacity: .65; padding: 10px 0 4px 0;}
"""

HERO = f"""
<div class="hero">
  <h1>Unplug <span style="opacity:.6">tiny</span></h1>
  <div class="tagline">Find the attack. Cut the attack. Keep the rest.</div>
  <div class="links">
    <a href="{MODEL_URL}" target="_blank">Model card</a> &nbsp;|&nbsp;
    <a href="{GITHUB_URL}" target="_blank">SDK on GitHub</a> &nbsp;|&nbsp;
    <code>pip install "unplug-ai[ml]"</code>
  </div>
  <div class="disclaimer">{DISCLAIMER}</div>
</div>
"""

ABOUT = f"""
**unplug-tiny-v1** is a dual-head span detector: a document head decides *whether* text is
hostile, a BIOES token head localizes *where* - so the pipeline redacts the malicious span
instead of dropping the whole document.

- **Policy:** `doc_or_span` - doc threshold 0.9, span threshold 0.60
- **Long documents:** sliding windows (2048 chars, 256 overlap) cover the full text
- **Encoded payloads:** Base64 blobs are decoded and classified
- **Regex baseline:** uncheck the ML box to compare against pattern matching alone

Honest, measured strengths and weaknesses - including failing axes - are on the
[model card]({MODEL_URL}). For a full agent kill chain (hidden webpage injection ->
tainted session -> blocked exfil tool call) see
[`agent_exfil_demo.py`]({EXFIL_URL}).
"""

FOOTER = f"""
<div class="footer">
  Built with the <a href="{GITHUB_URL}" target="_blank">Unplug SDK</a> | Apache-2.0 |
  Model: <a href="{MODEL_URL}" target="_blank">Unplug-AI/unplug-tiny-v1</a>
</div>
"""

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
                _guard_ml = Guard(model="tiny", auto_download_model=True, require_ml=True)
            return _guard_ml
        if _guard_regex is None:
            _guard_regex = Guard(
                scanners=["injection"],
                config=GuardConfig(active_model=None, auto_download_model=False),
            )
        return _guard_regex


def warm_start() -> None:
    """Preload the ML guard so the first visitor doesn't pay the cold start."""
    with contextlib.suppress(Exception):
        _get_guard(use_ml=True)


def _is_doc_level(finding: Finding, text_len: int) -> bool:
    span = finding.span_end - finding.span_start
    return text_len >= _DOC_LEVEL_MIN_CHARS and span >= _DOC_LEVEL_COVERAGE * text_len


def split_findings(findings: list[Finding], text_len: int) -> tuple[list[Finding], list[Finding]]:
    """Separate localized spans from document-level flags."""
    localized = [f for f in findings if not _is_doc_level(f, text_len)]
    doc_level = [f for f in findings if _is_doc_level(f, text_len)]
    return localized, doc_level


def highlight_segments(text: str, findings: list[Finding]) -> list[tuple[str, str | None]]:
    """Build (segment, label) pairs for gr.HighlightedText."""
    if not text:
        return [("", None)]
    spans = sorted(
        ((f.span_start, min(f.span_end, len(text)), f.category) for f in findings),
        key=lambda item: (item[0], item[1]),
    )
    segments: list[tuple[str, str | None]] = []
    pos = 0
    for start, end, label in spans:
        if end <= pos or end <= start:
            continue
        start = max(start, pos)
        if start > pos:
            segments.append((text[pos:start], None))
        segments.append((text[start:end], label))
        pos = end
    if pos < len(text):
        segments.append((text[pos:], None))
    return segments or [(text, None)]


def findings_rows(result: ScanResult) -> list[list[Any]]:
    return [
        [
            f.category,
            f.subcategory,
            f.span_start,
            f.span_end,
            round(f.score, 3),
            f.evidence[:120],
        ]
        for f in result.findings
    ]


def _verdict_html(
    result: ScanResult,
    *,
    use_ml: bool,
    doc_level: list[Finding],
) -> str:
    mode = "ML (unplug-tiny)" if use_ml else "regex baseline"
    detail = (
        f"<small>risk {result.risk_score:.2f} | {result.latency_ms:.0f} ms | "
        f"{len(result.findings)} finding(s) | mode: {mode}</small>"
    )
    if result.safe:
        return f'<div class="verdict verdict-safe">SAFE - nothing flagged<br>{detail}</div>'
    doc_note = ""
    if doc_level:
        doc_note = (
            "<br><small>Document-level classifier fired (no single localized span "
            " -  the whole text reads as hostile).</small>"
        )
    action = result.action.value.upper()
    cls = "verdict-review" if action == "REVIEW" else "verdict-block"
    return f'<div class="verdict {cls}">{action} - threat detected<br>{detail}{doc_note}</div>'


def _expectation_note(text: str) -> str:
    for meta in load_examples().values():
        if meta["text"].strip() == text.strip():
            expected = meta["expected"]
            status = meta.get("status", "supported")
            prefix = "🛣️ Roadmap" if status == "roadmap" else "✓ Supported"
            return f"**{meta['label']}** ({prefix}) - expected: `{expected}`. {meta['note']}"
    return ""


def analyze(
    text: str, use_ml: bool
) -> tuple[str, str, list[tuple[str, str | None]], str, list[list[Any]]]:
    if not text.strip():
        idle = '<div class="verdict verdict-idle">Paste text and press Scan.</div>'
        return idle, "", [("", None)], "", []

    try:
        guard = _get_guard(use_ml=use_ml)
        result = guard.scan(text, source="user")
    except Exception as exc:  # surface failure in the UI, fail closed
        err = (
            '<div class="verdict verdict-block">SCANNER ERROR - failing closed<br>'
            f"<small>{type(exc).__name__}</small></div>"
        )
        return err, "", [(text, None)], "", []

    localized, doc_level = split_findings(result.findings, len(text))
    verdict = _verdict_html(result, use_ml=use_ml, doc_level=doc_level)
    note = _expectation_note(text)
    segments = highlight_segments(text, localized)
    redacted = result.redacted_text if result.redacted_text is not None else text
    return verdict, note, segments, redacted, findings_rows(result)


def build_demo() -> gr.Blocks:
    examples = load_examples()
    supported = [meta for meta in examples.values() if meta.get("status", "supported") != "roadmap"]
    roadmap = [meta for meta in examples.values() if meta.get("status") == "roadmap"]
    example_rows = [[meta["text"], True] for meta in supported]
    roadmap_rows = [[meta["text"], True] for meta in roadmap]

    theme = gr.themes.Soft(
        primary_hue=gr.themes.colors.emerald,
        neutral_hue=gr.themes.colors.slate,
    )

    with gr.Blocks(theme=theme, css=CSS, title="Unplug Tiny - prompt injection scanner") as demo:
        gr.HTML(HERO)

        with gr.Row(equal_height=False):
            with gr.Column(scale=5):
                text_in = gr.Textbox(
                    label="Untrusted text",
                    lines=12,
                    placeholder="Paste a user message, RAG chunk, tool output, or web page...",
                )
                use_ml = gr.Checkbox(
                    value=True,
                    label="ML model (unplug-tiny) - uncheck for regex-only baseline",
                )
                with gr.Row():
                    gr.ClearButton([text_in], value="Clear")
                    scan_btn = gr.Button("Scan", variant="primary")

            with gr.Column(scale=7):
                verdict_out = gr.HTML(
                    value='<div class="verdict verdict-idle">Paste text and press Scan.</div>'
                )
                note_out = gr.Markdown()
                highlight_out = gr.HighlightedText(
                    label="Detected spans",
                    color_map=COLOR_MAP,
                    combine_adjacent=True,
                    show_legend=True,
                )
                redacted_out = gr.Textbox(label="Redacted output", lines=6)
                findings_out = gr.Dataframe(
                    headers=["category", "subcategory", "start", "end", "score", "evidence"],
                    label="Findings",
                    interactive=False,
                )

        outputs = [verdict_out, note_out, highlight_out, redacted_out, findings_out]

        gr.Examples(
            examples=example_rows,
            inputs=[text_in, use_ml],
            outputs=outputs,
            fn=analyze,
            run_on_click=True,
            cache_examples=False,
            label="Supported test cases (regex + ML)",
            examples_per_page=7,
        )

        if roadmap_rows:
            gr.Examples(
                examples=roadmap_rows,
                inputs=[text_in, use_ml],
                outputs=outputs,
                fn=analyze,
                run_on_click=True,
                cache_examples=False,
                label="Roadmap: planned for a future release",
                examples_per_page=3,
            )

        with gr.Accordion("About this model", open=False):
            gr.Markdown(ABOUT)

        gr.HTML(FOOTER)

        scan_btn.click(analyze, inputs=[text_in, use_ml], outputs=outputs)
        text_in.submit(analyze, inputs=[text_in, use_ml], outputs=outputs)

    return demo


def main() -> None:
    threading.Thread(target=warm_start, daemon=True).start()
    build_demo().launch()


if __name__ == "__main__":
    main()
