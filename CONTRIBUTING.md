# Contributing to Unplug

**Unplug the bad AI.**

## Getting started (fork workflow)

1. Fork [UnplugAI/Unplug](https://github.com/UnplugAI/Unplug) and clone your fork.
2. Set up the SDK:

```bash
cd sdk
uv sync --all-extras --dev   # everything, including optional extras
# or minimal core only:
uv sync --dev
```

3. Optional extras map to scanner features and integrations — install only what you touch:

| Extra | Enables |
|-------|---------|
| `ml` | ML span model (`Guard(model="tiny")`) |
| `yara` | YARA code/SQLi/XSS scanner |
| `presidio` | Presidio PII scanner |
| `litellm` | LLM judge for borderline cases |
| `haystack` | Haystack RAG integration |
| `scrape` | Firecrawl content provider |
| `langgraph` | LangGraph node hooks |
| `langchain` | LangChain Runnable + callback hooks |
| `openai-agents` | OpenAI Agents SDK guardrails |
| `google-adk` | Google ADK before-model / before-tool callbacks |
| `smolagents` | smolagents task + final-answer checks |
| `crewai` | CrewAI task/output guards |
| `autogen` | Microsoft AutoGen AgentChat hooks |
| `agno` | Agno pre/post run hooks |
| `dspy` | DSPy module guards |
| `strands` | Strands Agents hook provider |
| `letta` | Letta message guards |
| `griptape` | Griptape before/after run hooks |
| `atomic-agents` | Atomic Agents schema guards (Python ≥3.12) |
| `llama-index` | LlamaIndex node postprocessor |
| `pydantic-ai` | Pydantic AI validators |
| `semantic-kernel` | Semantic Kernel filters |
| `mcp` | MCP client-side tooling tests |
| `integrations` | **Meta-extra:** all framework extras above |
| `all` | ML + presidio + yara + scrape + haystack + litellm |

Integration guides: [`sdk/integrations/README.md`](sdk/integrations/README.md). New contributor docs: [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md), [`docs/AGENT_ACTIONS.md`](docs/AGENT_ACTIONS.md).

4. Verify your environment: `make check` (lint + format + tests).

## Claiming an issue

Comment on the issue saying you want it, and wait for a maintainer to assign it
to you. Assignment usually happens within a day.

Do not start writing code before the issue is assigned. It is the only way we can
stop two people building the same thing, and we would rather tell you an issue is
already spoken for than have you find out at review time.

One issue at a time. When the PR for it is merged, we assign you the next one.

That is not a judgement on how fast you work. An assigned issue looks taken to
everyone else, so two parked issues means two people who could have picked
something up and did not. Ask for the next one whenever you like and we will
queue it against your name.

If an issue is already assigned, leave it alone, even if it has been quiet for a
while. Ask on the issue if you think something has stalled.

Maintainers assign issues to themselves directly, since there is nobody for them
to collide with.

If you go quiet for a couple of weeks we will ask whether you are still on it
before freeing it up. We will always ask you first.

## Mentored issues

Issues labelled [`mentored`](https://github.com/UnplugAI/Unplug/labels/mentored)
come with a maintainer attached. They are for people who want to learn the codebase,
not just people who already know it.

What that means in practice:

- The issue tells you which file to open and which test should exist when you are done.
- Ask anything on the issue thread. "I do not understand what taint propagation is
  for" is a fine question. So is "I have been stuck on this import error for an hour".
- We will review a half-finished PR if you want a check on direction. Open it as a
  draft and say what you are unsure about.
- Getting it wrong first try is expected. Nobody's first patch to a security scanner
  is right.

A mentored issue is still one issue. The one-at-a-time rule above applies here too,
and we would rather you finish this one with help than juggle two.

Two things we ask in return. Tell us when you get stuck rather than disappearing, and
write the patch yourself. Reading an explanation is the point of the label. If a model
writes it for you there is nothing left to learn, and [AI_POLICY.md](AI_POLICY.md)
applies here the same as anywhere else.

If you want a mentored issue but none are open, say so in
[Discussions](https://github.com/UnplugAI/Unplug/discussions/categories/q-a) and we
will label one.

## Using AI to write your patch

Allowed, and you have to disclose it. Undisclosed AI-generated PRs get closed.
Full policy: [AI_POLICY.md](AI_POLICY.md).

## Branching and PRs

- Do **not** push directly to `main`.
- Branch from **`dev`**: `feature/<short-name>` or `fix/<short-name>`.
- Open a PR targeting **`dev`**; iterate in review until green CI.
- Merge via squash or merge commit after approval.
- `main` is release-only — see [`.github/BRANCHING.md`](.github/BRANCHING.md).
- Releases are tagged from `main` and published by maintainers — see [`sdk/PUBLISH.md`](sdk/PUBLISH.md).

## What not to commit

- Internal strategy, competitive analysis, or business planning docs
- Agent session transcripts or private `.context/` material
- Secrets (`.env`, API keys, credentials)

Keep internal notes local or in a private repository.

## CI

GitHub Actions runs on every PR to `dev` ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):

1. **Ruff** — `ruff check .` + `ruff format --check .`
2. **Tests** — full pytest suite (`pytest -q`)
3. **Exfil demo gate** — `test_exfil_demo_integration.py` + `sdk/examples/agent_exfil_demo.py`
4. **Security regression** — explicit subset (adversarial, encodings, secrets, agent hardening, etc.)
5. **Coverage** — SDK coverage report with an 80% minimum gate (`make test-cov`)

## Local checks (SDK)

Install the hooks once and ruff stops being a CI failure:

```bash
uv tool install pre-commit
pre-commit install
```

The hooks are the fast half of `make check`. They do not run mypy or the test suite,
so still run `make check-ci` before you open the PR.

```bash
cd sdk
uv sync --all-extras --dev

# Fast local gate (lint + format + full pytest)
make check

# Exact CI parity before PR (includes exfil demo + security subset)
make check-ci

# Docs drift only: every `from unplug import ...` in the docs must resolve
make check-docs

# Coverage report and 80% minimum gate
make test-cov

# Auto-fix formatting and safe lint fixes
make fix

# Individual targets
make lint
make format
make test
make test-security
make audit
make audit-ml
```

From repo root: `make check`, `make check-ci`, `make fix`, `make test`.

## Test layout

`sdk/tests/` mirrors `sdk/src/unplug/`:

```bash
uv run pytest tests/unit           # fast, no optional deps
uv run pytest tests/unit/core      # core subpackages (taint, normalize, policy, ...)
uv run pytest tests/integration    # Guard end-to-end, client, examples
uv run pytest tests/security       # adversarial + regression gate
uv run pytest tests/optional       # presidio / yara / haystack / litellm (skip when extras missing)
```

Every new module gets a test file in the mirrored location.

ML checkpoint tests skip unless `UNPLUG_TEST_CHECKPOINT` (or `UNPLUG_MODEL_PATH`)
points at a local checkpoint directory — see `.env.example`.

## Code conventions

- Python 3.11+, `uv`, ruff, pytest
- `from __future__ import annotations` in every file
- Type all function parameters and return values
- Pydantic `BaseModel` for data models
- Architecture layering: Guard → Pipelines → Scanners → Core
- Fail closed: scanner/pipeline errors → block, never allow silently
- Import scanners from **`unplug.scanners.*`** (canonical namespace)

## Agent integration

When adding scanner or pipeline behavior, read the **agent host checklist** in [`sdk/README.md`](sdk/README.md) and run `unplug-audit` (plus `--probes` when touching detection).

## Related repos

| Repo | Role |
|------|------|
| [Unplug](https://github.com/UnplugAI/Unplug) | SDK (this repo) |
| [unplug-server](https://github.com/UnplugAI/unplug-server) | Hosted API |
| [unplug-mcp](https://github.com/UnplugAI/unplug-mcp) | MCP tools |

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
