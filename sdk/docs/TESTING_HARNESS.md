# Testing harness (pre-release / local)

Commands for validating the SDK before a release cut. Run from `sdk/` after
`uv sync --all-extras --dev` (or a narrower extra set — see below).

## Quick commands

| Target | What it runs |
|--------|----------------|
| `make check-ci` | Lint, mypy, format check, full pytest, exfil demo, security + ML integration subset, scenarios, attack gate |
| `make test-cov` | Pytest with coverage; fails under 80% |
| `make test-frameworks` | Agent matrix + adapter tests (no agent SDK installs) |
| `make test-frameworks-live` | `tests/optional/live/` (needs framework extras; skips if missing) |
| `make test-ml` | ML unit + Guard ML integration |
| `make test-ml-harness` | `test-ml` + weight-backed smoke/audit when checkpoint present + offline hooks smoke |
| `make smoke-ml` | `scripts/smoke_local_ml.py` + `unplug-audit --require-ml` |
| `make smoke-ml-hooks` | Offline synthetic checkpoint + Guard + LangGraph-style hooks |
| `make examples` | Demo scripts + `tests/integration/test_examples.py` |
| `make test-all-local` | `check-ci` + `test-cov` + `test-frameworks` + `test-ml-harness` + `examples` |

One-liner for a thorough local pass:

```bash
cd sdk && make test-all-local
```

## Extras

| Install | Needed for |
|---------|------------|
| `uv sync --dev` / `pip install -e ".[dev]"` via `--group dev` | Core unit/integration/security |
| `unplug-ai[ml]` / `--extra ml` | `test-ml`, `smoke-ml-hooks`, ML unit fixtures |
| Real checkpoint (`unplug-models download tiny` or `UNPLUG_MODEL_PATH`) | `smoke-ml`, `audit-ml`, `@pytest.mark.requires_ml_weights` |
| `unplug-ai[langgraph]` (etc.) or `unplug-ai[integrations]` | Live framework tests only |
| Capability extras (`yara`, `presidio`, `haystack`, …) | Matching `tests/optional/` modules |

Notes:

- Default CI (`make check-ci` on 3.11/3.12) uses `uv sync --all-extras --dev`, which
  pulls **capability** extras (`ml`, `scrape`, …) but **not** every agent framework.
  Agent SDKs install via the `integrations` meta-extra or one framework at a time.
- Live framework coverage is a separate workflow (`.github/workflows/integrations-live.yml`).
  Details: [`integrations/TESTING.md`](../integrations/TESTING.md).

## CI vs local-only

| Suite | CI (PR → `dev`) | Local |
|-------|-----------------|-------|
| Lint / mypy / format / pytest | Yes (`check-ci`, 3.11–3.12; 3.13 regex-only) | `make check` / `check-ci` |
| Coverage ≥ 80% | Yes (3.12 job) | `make test-cov` |
| Security matrix + adapters | Yes (inside `check-ci` / security paths) | `make test-frameworks` |
| Scenarios + attack gate | Yes | `make scenarios` / `attack-gate` |
| ML unit (synthetic ckpt) | Yes when `[ml]` installed | `make test-ml` |
| Weight-backed ML smoke/audit | Only if runner has weights (usually skip) | `make smoke-ml` after download |
| Offline ML+hooks smoke | Not in CI gate | `make smoke-ml-hooks` |
| Examples demos | Partial (exfil in `check-ci`) | `make examples` |
| Live framework imports | `integrations-live` workflow (path/nightly) | `make test-frameworks-live` |
| Docker E2E | No | `make docker-e2e` (`RUN_DOCKER_E2E=1`) |

## ML checkpoint

Weight-backed tests skip when no checkpoint is found:

```bash
# Preferred: cache via CLI
uv run unplug-models download tiny

# Or point at a local checkpoint-slim dir
export UNPLUG_MODEL_PATH=/path/to/checkpoint
export UNPLUG_ACTIVE_MODEL=tiny
```

Resolution order: `UNPLUG_TEST_CHECKPOINT` → `UNPLUG_MODEL_PATH` →
`configs/ml_validation.json` `checkpoint_relative` (workspace) →
`$UNPLUG_MODEL_CACHE/<tier>/checkpoint` (default `~/.cache/unplug/models/tiny/checkpoint`).
See [`ML_INTEGRATION.md`](ML_INTEGRATION.md).

Without weights:

- `make test-ml` / ML unit tests still run (synthetic checkpoints in `tests/unit/ml/`).
- `@pytest.mark.requires_ml_weights` cases **skip**.
- `make smoke-ml` / `audit-ml` **fail** if invoked directly — use `make test-ml-harness`,
  which skips `smoke-ml` when weights are absent and still runs `smoke-ml-hooks`.

## Framework matrix (no SDK installs)

```bash
uv run pytest tests/security/test_agent_integration_matrix.py -v
# or
make test-frameworks
```

Related adapter tests: `tests/integration/test_integration_adapters.py`,
`tests/integration/test_integrations.py`, `tests/unit/integrations/`.

## Offline ML + hooks smoke

```bash
make smoke-ml-hooks
# → scripts/smoke_ml_hooks.py
```

Builds a tiny random BIOES checkpoint in a temp dir, loads `Guard.with_tiny`, and
runs LangGraph-style input/tool hooks. Proves wiring without hub access or
`langgraph` installed. Does **not** assert ML recall (weights are random).
