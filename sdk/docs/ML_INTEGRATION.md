# ML integration checklist (dual-head v1.21+)

Ship after golden gates pass on the GPU run. Do not publish weights until `reports/golden.json` shows all required gates green.

## Checkpoint layout

Slim export from `unplug_exp/scripts/export_slim_checkpoints.py`:

```
checkpoint-slim/
  config.json          # dual_head: true, doc_positive_index, label2id
  model.safetensors
  tokenizer.json
  thresholds.json      # optional sidecar from calibration
```

## SDK wiring

1. Install ML extras: `pip install "unplug-ai[ml]"`
2. Copy slim checkpoint locally or set `UNPLUG_MODEL_PATH`
3. Enable in `unplug.toml`:

```toml
active_model = "small"

[models.small]
name = "unplug-small"
backend = "transformers_span"
path = "/path/to/checkpoint-slim"

[models.small.config]
max_length = 512
inj_threshold = 0.5
doc_threshold = 0.95   # from configs/thresholds.json after calibration
device = "auto"
```

4. Verify:

```bash
unplug-audit --require-ml
unplug-audit --probes
python examples/agent_exfil_demo.py
```

## Dual-head behavior

| Head | SDK subcategory | When it fires |
| --- | --- | --- |
| Token / BIOES | `span_model` | Localized injection span above `inj_threshold` |
| Document | `doc_head` | No spans, but doc classifier ≥ `doc_threshold` |

Encoding blobs (Base64) use the same thresholds via decode-then-classify.

## Release artifacts

- `BENCHMARKS.md` — auto-generated from golden eval (no hand-typed numbers)
- PyPI `unplug-ai` version bump after gate review
- HuggingFace model repo (optional) pointing at slim checkpoint

## v1.22 fallback

If v1.21 fails FPR gates, rebuild data with `./scripts/prepare_v122_fallback.sh` in `unplug_exp` before retraining. See `docs/V122_FALLBACK_DATA_PLAN.md`.
