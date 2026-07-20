# Unplug PR agent scan (composite action)

Scan **agent-related files changed in a PR** with the unplug-ai regex Guard. Intended for repos that ship `AGENTS.md`, `.cursor/rules`, or MCP client configs.

**External repos:** prefer the published Marketplace action **[UnplugAI/unplug-scan-action@v1](https://github.com/UnplugAI/unplug-scan-action)** (PyPI install, semver tags).

This composite action lives in the monorepo for local SDK development.

## Usage in this repo

Already wired in [`.github/workflows/pr-scan.yml`](../workflows/pr-scan.yml).

## Usage in another repository

```yaml
jobs:
  unplug-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - uses: UnplugAI/Unplug/.github/actions/unplug-scan@dev
        with:
          base-ref: main
          install-mode: pypi
          unplug-version: ">=0.5.0,<0.6"
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `base-ref` | `dev` | Base branch for `git diff origin/<base-ref>...HEAD` |
| `python-version` | `3.12` | Python version |
| `working-directory` | `sdk` | Path to SDK tree when `install-mode: local` |
| `install-mode` | `local` | `local` (uv sync) or `pypi` (install from PyPI) |
| `unplug-version` | `>=0.5.0,<0.6` | Version constraint for PyPI install |

## What gets scanned

Files matching any of:

- `AGENTS.md` / `AGENT.md`
- `.cursor/` (rules, hooks, MCP config)
- `mcp.json`, `claude_desktop_config`

Test fixtures, docs, and `.github/` paths are skipped automatically.

## Local CLI

```bash
pip install unplug-ai
unplug-scan-pr --base-ref dev
```
