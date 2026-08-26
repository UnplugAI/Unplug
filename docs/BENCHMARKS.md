# SDK benchmark results

- **Date:** 2026-08-25
- **Guard:** `unplug-ai`, default scanners
- **Model:** `unplug-tiny-v1` (DeBERTa-v3-xsmall dual-head span model), `Guard(model="tiny")`
- **Detection threshold:** risk >= 0.5 counts as flagged (block or review)
- **Split:** `neuralchemy/Prompt-injection-dataset` `core/test` (942 rows). `unplug-tiny`
  was fine-tuned on `core/train`, so any score measured there is memorisation, not
  detection. Earlier revisions of this page reported the train split by mistake.
- **Methodology:** isolated single-turn sessions. Each sample is scanned in a fresh
  `ExecutionContext` (`scan_request(..., isolated=True)`), so multi-turn trajectory
  state never leaks between independent samples.

Phase C gap notes and download commands: [`EVAL_PHASE_C.md`](EVAL_PHASE_C.md).

## Headline: regex vs regex + ML

The tiny tier second-passes every scan with the ML model, so it catches injections
the regex layer alone misses (especially **indirect** injection).

| Dataset | Samples | Mode | F1 | Recall | FPR | Precision |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| neuralchemy `core/test` | 942 | regex-only | 0.519 | 0.351 | 0.0026 | 0.995 |
| neuralchemy `core/test` | 942 | **regex + ML** | **0.974** | **0.958** | 0.0128 | 0.991 |
| microsoft/llmail-inject (Phase1 subset, attacks) | 2,500 | regex-only | n/a | 0.052 | n/a | n/a |
| microsoft/llmail-inject (Phase1 subset, attacks) | 2,500 | **regex + ML** | n/a | **0.907** | n/a | n/a |

- **Direct injection (neuralchemy):** recall **0.35 -> 0.96**, F1 **0.52 -> 0.97**.
  Precision holds near 0.99 in both modes. The ML pass costs false positives:
  FPR goes from 1 false positive in 390 benign rows to 5.
- **Indirect injection (microsoft):** recall **0.05 -> 0.91**. Regex is structurally
  blind to indirect injection; the ML pass is what makes it detectable. We have not
  confirmed whether any of this subset overlaps `unplug-tiny` fine-tuning data, so
  read that row as an upper bound.

## What changed on 2026-08-25

This page used to report `core/train`: 0.987 F1 and 0.981 recall for regex + ML.
That split is the model's own fine-tuning data. On the held-out `core/test` split the
same build scores 0.974 F1 and 0.958 recall, so contamination was worth about 2.3
points of recall.

Regex-only moved too, 0.405 recall down to 0.351, and regex has no training data at
all. Part of the gap is that the two splits are not equally hard, not memorisation.

## False-positive rate on clean traffic

A committed corpus of 135 prompts (`benchmarks/data/benign_ci.jsonl`): the original 95 plus 40 new hard negatives that contain trigger vocabulary.


| Mode | Slice | False positives | FPR |
|------|-------|-----------------|-----|
| regex-only | original 95 | 0 / 95 | 0.000 |
| regex-only | hard negatives (40) | 39 / 40 | 0.975 |
| regex + ML | original 95 | 2 / 95 | 0.021 |

The two ML false positives are one soft `abstain → review` ("explain how photosynthesis
works") and one genuine model error ("explain the theory of relativity", scored 0.99).
The first is a *review*, not a block. The `inj_threshold` is tuned to **0.60** (the
recall/FPR knee) to keep this rate low without sacrificing recall.

> **Note on the FPR.** These 40 hard negatives were chosen *because* they trip the
> patterns. The regex-only 0.975 FPR on that slice (and the 0.289 on the full 135)
> is therefore **not a population false-positive rate** - it is the rate on a corpus
> deliberately built to be hard.

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

## Where it does badly

Detection numbers on corpora we did not pick are worse, and the false-positive rate on
broad benign traffic is much worse. From the `unplug-tiny-v1` model card, which runs a
frozen harness over public sets:

| Set | Recall | Doc FPR | F1 |
| --- | ---: | ---: | ---: |
| BIPIA indirect proxy (1,242) | 0.973 | 0.000 | 0.986 |
| InjecGuard validation (144) | 0.896 | 0.208 | 0.775 |
| Deepset full (662) | 0.829 | 0.188 | 0.784 |
| spikee contextual (986) | 0.786 | 0.067 | 0.879 |
| LLM-PIEval agentic (750) | 0.761 | n/a | 0.865 |
| OOD direct injection (281) | 0.619 | 0.102 | 0.692 |
| WildGuard benign (971) | n/a | 0.542 | n/a |
| Combined public validation (3,227) | 0.810 | 0.341 | 0.717 |

One third of benign prompts in the combined public set get flagged. If your traffic
looks like WildGuard rather than like our benign corpus, expect over-blocking, and
tune the threshold before you put this in front of users. The model card carries the
per-axis failure modes and marks three of its own gates as failing.

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
| [`ci.yml`](https://github.com/UnplugAI/Unplug/blob/dev/.github/workflows/ci.yml) | Lint + mypy + pytest matrix (3.11–3.13) + attack-harness gate |
| [`pr-scan.yml`](https://github.com/UnplugAI/Unplug/blob/dev/.github/workflows/pr-scan.yml) | Regex scan on changed agent/MCP config files |
| [`reusable-agent-scan.yml`](https://github.com/UnplugAI/Unplug/blob/dev/.github/workflows/reusable-agent-scan.yml) | `workflow_call` entry for other repos |

The attack-harness gate (`benchmarks/attacks/ci_gate.py`) enforces per-category recall
floors on the committed garak corpus and a benign false-positive ceiling.
