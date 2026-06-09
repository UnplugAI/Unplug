# Unplug

LLM defense layer — SDK package.

## Commands

```bash
make install          # install SDK
make check            # lint + format --check + full pytest
make check-ci         # CI parity: check + exfil demo + security subset
make fix              # auto-fix lint + format
make test             # run all tests
make test-security    # security regression subset (verbose)
make lint             # ruff check
make format           # ruff format

cd sdk && uv sync --all-extras --dev
cd sdk && make check-ci
```

## Structure

- `sdk/` — Python SDK (`pip install unplug-ai`, import `unplug`)
  - `src/unplug/safeguards/` — **canonical** threat scanners + registry
  - `src/unplug/scanners/` — deprecation shims only (remove at major version)
  - `src/unplug/pipelines/` — input, output, toolcall pipelines
  - `src/unplug/audit/` — `unplug-audit` wiring + probe batteries
  - `src/unplug/ml/` — model cache, catalog, download-once store

Server, MCP, and site live in separate repos:
- [unplug-server](https://github.com/chiruu12/unplug-server)
- [unplug-mcp](https://github.com/chiruu12/unplug-mcp)
- [unplug-site](https://github.com/chiruu12/unplug-site)

## Conventions

- Python 3.11+, uv, ruff, pytest
- `uv add <package>` — never edit pyproject.toml manually
- `from __future__ import annotations` in every file
- Tests alongside code — every module gets a test file
- Read existing files before creating new ones
- Fail closed — errors default to blocking

## Commits

- One line, under 50 chars
- Describe what shipped, not how
- Never expose internal process
