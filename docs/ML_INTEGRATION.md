# ML integration

How to enable the ML span model on top of the regex core.

## Checkpoint layout

A checkpoint directory needs:

```
checkpoint-slim/
  config.json          # dual_head: true, doc_positive_index, label2id
  model.safetensors
  tokenizer.json
  thresholds.json      # optional sidecar from calibration
```

## Hugging Face model (recommended)

Public preview weights: **`Unplug-AI/unplug-tiny-v1`** (dual-head span model).

The bundled catalog in `src/unplug/data/catalog.toml` pins this repo. Enable auto-download:

```toml
# unplug.toml
active_model = "tiny"
auto_download_model = true
require_ml = false   # set true to fail-fast if weights missing
```

Or in Python:

```python
from unplug import Guard

guard = Guard(model="tiny", auto_download_model=True, require_ml=False)
result = guard.scan(user_text)
```

Manual download (optional):

```bash
pip install "unplug-ai[ml]"
unplug-models download tiny
```

## Local checkpoint override

1. Install ML extras: `pip install "unplug-ai[ml]"`
2. Set `UNPLUG_MODEL_PATH=/path/to/checkpoint-slim` or configure in `unplug.toml`:

```toml
active_model = "tiny"

[models.tiny]
name = "unplug-tiny"
backend = "transformers_span"
path = "/path/to/checkpoint-slim"

[models.tiny.config]
max_length = 512
stride = 64
inj_threshold = 0.45
doc_threshold = 0.9
device = "auto"
batch_size = 4
```

## Long-text and streaming

Defaults in `catalog.toml` for the `tiny` tier:

| Key | Default | Meaning |
| --- | --- | --- |
| `long_text_mode` | `sliding` | Full-document coverage via overlapping windows (`head_tail` still available) |
| `long_text_threshold_chars` | `8192` | Start chunking above this length |
| `long_text_chunk_chars` | `2048` | Window size in characters |
| `long_text_overlap_chars` | `256` | Overlap between windows |

Within each window, token stride inference uses `max_length=512` and `stride=64`.

Streaming helpers (`unplug.streaming`):

```python
scanner = guard.stream_scanner(scan_every_chars=1024)
# push chunks as they arrive; flush() at end of stream
guard.scan_stream(["chunk1", "chunk2"])
```

## Verify

```bash
unplug-audit --require-ml
unplug-audit --probes
python examples/agent_exfil_demo.py
```

## ABSTAIN band

When `abstain_enabled` is true (default in `catalog.toml`), the ML scanner uses a three-way band:

- **BLOCK**: doc or span score above threshold
- **ALLOW**: scores below `tau_abstain_low` with no span fire
- **ABSTAIN**: uncertain middle band → `Action.ABSTAIN`; localized spans are redacted
  when present, while document-only abstentions must stay blocked pending review

Optional `JudgeProvider` runs when passed as `judge=` to `Guard()` — on ML ABSTAIN
or when max scanner risk is in `[judge_low, judge_high)` (defaults 0.3–0.8). See
[`LIMITS_AND_JUDGE.md`](LIMITS_AND_JUDGE.md).

## Dual-head behavior

| Head | SDK subcategory | When it fires |
| --- | --- | --- |
| Token / BIOES | `span_model` | Localized injection span above `inj_threshold` |
| Document | `doc_head` | No spans, but doc classifier ≥ `doc_threshold` |

Encoding blobs (Base64) use the same thresholds via decode-then-classify.

## Release artifacts

- `BENCHMARKS.md`: maintained from evaluation-harness results; verify recorded numbers against
  the cited command and dataset before publishing
- PyPI `unplug-ai` version bump after gate review
- Hugging Face model repo: `Unplug-AI/unplug-tiny-v1`
