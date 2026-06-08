# Contributing to Unplug

## Branching and PRs

- Do **not** push directly to `main`.
- Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
- Open a PR; iterate in review until green CI.
- Merge via squash or merge commit after approval.

## CI

GitHub Actions runs on every PR to `main` (`/.github/workflows/ci.yml`):

1. **Ruff** — `ruff check .` + `ruff format --check .`
2. **Tests** — full pytest suite (`pytest -q`)
3. **Exfil demo gate** — `test_exfil_demo_integration.py` + `examples/agent_exfil_demo.py`
4. **Security regression** — explicit subset:
   - `test_adversarial.py`
   - `test_false_positives.py`
   - `test_encodings.py`
   - `test_secrets.py`
   - `test_scan_policy.py`
   - `test_security_stress.py`
   - `test_sdk_coverage.py`
   - `test_agent_hardening.py`

## Local checks (SDK)

```bash
cd sdk
uv sync --all-extras --dev

# Fast local gate (lint + format + full pytest)
make check

# Exact CI parity before PR (includes exfil demo + security subset above)
make check-ci

# Auto-fix formatting and safe lint fixes
make fix            # ruff check --fix + ruff format

# Individual targets
make lint           # ruff check only
make format         # ruff format only
make test           # pytest -v
make test-security  # security subset + test_financial (verbose)
make audit          # unplug-audit wiring
make audit-ml       # unplug-audit --require-ml
```

From repo root (`jakarta/`): `make check`, `make check-ci`, `make fix`, `make test`.

## Code conventions

- Import scanners from **`unplug.safeguards.*`** — not `unplug.scanners.*` (deprecated shims)
- Fail closed: scanner/pipeline errors → block, never allow silently
- All new modules: `from __future__ import annotations`, typed params/returns, Pydantic models

## Agent integration

When adding scanner or pipeline behavior, read the **agent host checklist** in [`sdk/README.md`](sdk/README.md) and run `unplug-audit` (plus `--probes` when touching detection).

## Related repos

| Repo | Role |
|------|------|
| [Unplug](https://github.com/chiruu12/Unplug) | SDK (this repo) |
| [unplug-server](https://github.com/chiruu12/unplug-server) | Hosted API |
| [unplug-mcp](https://github.com/chiruu12/unplug-mcp) | MCP tools |

Server-heavy work (Postgres cache, Prompt Guard, BIOES, unplug-safeguard model) lives in **unplug-server** after the finetuned model is ready.
