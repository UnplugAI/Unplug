# SDK benchmark results

Date: 2026-06-15 (ML rows); regex-only neuralchemy refreshed **2026-07-20** (Phase C)
Guard: `unplug-ai`, default scanners
Model: `unplug-tiny-v1` (DeBERTa-v3-xsmall dual-head span model), `Guard(model="tiny")`
Detection threshold: risk ≥ 0.5 counts as flagged (block or review)
Methodology: **isolated single-turn sessions** — each sample is scanned in a fresh
`ExecutionContext` (`scan_request(..., isolated=True)`), so multi-turn trajectory
state never leaks between independent samples.

Phase C gap notes and download commands: [`EVAL_PHASE_C.md`](EVAL_PHASE_C.md).

## Headline: regex vs regex + ML

The tiny tier second-passes every scan with the ML model, so it catches injections
the regex layer alone misses (especially **indirect** injection).

| Dataset | Samples | Mode | F1 | Recall | FPR | Precision |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| neuralchemy/Prompt-injection-dataset | 4,391 | regex-only | 0.575 | 0.405 | 0.0052 | 0.992 |
| neuralchemy/Prompt-injection-dataset | 4,391 | **regex + ML** | **0.987** | **0.981** | 0.0098 | 0.994 |
| microsoft/llmail-inject (Phase1 subset, attacks) | 2,500 | regex-only | — | 0.052 | — | — |
| microsoft/llmail-inject (Phase1 subset, attacks) | 2,500 | **regex + ML** | — | **0.907** | — | — |

- **Direct injection (neuralchemy):** recall **0.41 → 0.98**, F1 **0.58 → 0.99**, precision ~0.99 in both modes, false-positive rate stays under 1%.
- **Indirect injection (microsoft):** recall **0.05 → 0.91**. Regex is structurally blind to indirect injection; the ML pass is what makes it detectable.

## False-positive rate on clean traffic

A committed corpus of 95 obviously-benign prompts (`benchmarks/data/benign_ci.jsonl`):

| Mode | False positives | FPR |
| --- | ---: | ---: |
| regex-only | 0 / 95 | 0.000 |
| regex + ML | 2 / 95 | 0.021 |

The two ML false positives are one soft `abstain → review` ("explain how photosynthesis
works") and one genuine model error ("explain the theory of relativity", scored 0.99).
The first is a *review*, not a block. The `inj_threshold` is tuned to **0.60** (the
recall/FPR knee) to keep this rate low without sacrificing recall.

## Honest caveats

- **The model only helps when it runs.** Before this tuning, the tiny tier shipped a
  conservative gate that only invoked ML when regex was *already* suspicious, so the
  model added ~0 recall out of the box. The tier now ships recall mode in `catalog.toml`
  (`ml_gate.always_below_high = true`).
- **Numbers are single-turn.** Trajectory/crescendo detection (a multi-turn feature)
  is intentionally not exercised here; it is measured separately.
- **Hard-negative precision is regex-driven.** On benign text that contains
  trigger-shaped phrases, the regex layer is the dominant false-positive source, not ML.
- The microsoft subset is attacks-only (recall, no FPR). neuralchemy carries both
  labels.

## Reproduce

```bash
cd sdk
uv sync --all-extras --dev
uv run python -m benchmarks.download --dataset all --out benchmarks/data

# regex-only
uv run python -m benchmarks.run benchmarks/data/neuralchemy.jsonl --isolated --format json

# regex + ML (downloads unplug-tiny-v1 from Hugging Face on first run)
uv run python -m benchmarks.run benchmarks/data/neuralchemy.jsonl --ml --isolated --format json
uv run python -m benchmarks.run benchmarks/data/microsoft_indirect.jsonl --ml --isolated --format json
```

## CI

PRs to `dev` run:

| Workflow | Purpose |
|----------|---------|
| [`ci.yml`](../../.github/workflows/ci.yml) | Lint + mypy + pytest matrix (3.11–3.13) + attack-harness gate |
| [`pr-scan.yml`](../../.github/workflows/pr-scan.yml) | Regex scan on changed agent/MCP config files |
| [`reusable-agent-scan.yml`](../../.github/workflows/reusable-agent-scan.yml) | `workflow_call` entry for other repos |

The attack-harness gate (`benchmarks/attacks/ci_gate.py`) enforces per-category recall
floors on the committed garak corpus and a benign false-positive ceiling.
