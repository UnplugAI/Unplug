# SDK benchmark results (regex-only Guard)

Date: 2026-06-11  
Guard: `unplug-ai` 0.2.1, default scanners, threshold 0.5  
Mode: regex-only (no `injection_ml`)

## Overall

| Dataset | Samples | F1 | Recall | FPR | Precision |
| --- | ---: | ---: | ---: | ---: | ---: |
| neuralchemy/Prompt-injection-dataset | 4,391 | 0.336 | 0.202 | 0.001 | 0.973 |
| microsoft/llmail-inject-challenge (Phase1 subset) | 5,000 | 0.080 | 0.042 | 0.000 | 1.000 |

Regenerate:

```bash
cd sdk
uv sync --group dev
uv run python -m benchmarks.download --dataset all --out benchmarks/data
uv run python -m benchmarks.run benchmarks/data/neuralchemy.jsonl --format json
uv run python -m benchmarks.run benchmarks/data/microsoft_indirect.jsonl --format json
```

## neuralchemy by category (lowest recall)

High precision, low recall: expand regex patterns, not thresholds. Full category breakdown is in eval JSON output.

| Category | Notes |
| --- | --- |
| system_extraction | Near-zero recall on smoke eval |
| crescendo / many_shot | Multi-turn; needs trajectory + more patterns |
| indirect_injection | Partial coverage; microsoft eval supplements |

## ML model benchmarks

Per-holdout metrics for `unplug-tiny-v1` live on the [model card](https://huggingface.co/Unplug-AI/unplug-tiny-v1). SDK regex numbers above are **not** comparable to ML golden gates.

## CI

PRs run `.github/workflows/pr-scan.yml` (regex scan on changed agent-related files).
