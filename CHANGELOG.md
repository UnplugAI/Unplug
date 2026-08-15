# Changelog

All notable changes to the `unplug-ai` SDK.

## [Unreleased]

### Fixed

- `injection` scanner no longer flags ordinary non-English text (Cyrillic, CJK) as `invisible_text`; the trigger is narrowed to genuine zero-width/bidi control characters and mixed-script homoglyph smuggling, and the finding span is scoped to the offending characters instead of the whole message (#121)

## [0.6.0] — 2026-07-20

### Security

- Safe-prefix cache: re-scan overlap at chunk boundaries and scope cache keys by source + policy fingerprint so split injection phrases and cross-source ALLOW reuse cannot bypass detection (#87, fixes #82/#83)
- Per-request `scanners=` allowlist no longer sticks on the shared `ExecutionContext`; omitted `scanners` clears the allowlist so later scans use the full configured set (#88, fixes #84)
- `Guard(config=GuardConfig(mode=...))` keeps the configured mode when `mode=` is not passed; `strict_scanner_allowlist` loads from TOML/`build_config`; unknown `[guard]` keys raise `ConfigError` (#89, fixes #85)
- Judge `action=block` / `review` / `allow` clamps finding scores so declared verdicts drive enforcement even when the LLM returns an inconsistent score (#90, fixes #86)
- Follow-up hardening from review debt: cache policy fingerprint + prefix overlap ≥ 1, strict-allowlist coercion, judge score enforcement, skip sensitive-context boost on `llm_judge`, hold ML inference lock through `predict_batch`, validate indexed shard checkpoints (#91)

### Added

- Public `LimitConfig` / BYOLLM judge surface (`unplug`, `unplug.api.limits`, `unplug.api.judge`) with docs, example, and TOML notes (#80)
- Focused injection regex patterns from neuralchemy FN sampling; bidi control stripping in the normalizer (#80)
- Pre-0.6.0 local test harness: `make test-frameworks`, `test-ml-harness`, `smoke-ml-hooks`, `test-all-local` plus `sdk/docs/TESTING_HARNESS.md` (#92)

### Fixed

- Post-merge review follow-ups across promote/Phase C: `unplug-scan` pin, AG2 multimodal redaction, model download flock/staging, tighter `instructions_updated_supersede` regex, `NORMALIZER_VERSION` bump, sharded safetensors checkpoints (#81)

### Changed

- Eval docs refreshed (`EVAL_PHASE_C.md` / benchmarks); regex neuralchemy recall/F1 improved modestly after pattern expansion (#80)

## [0.5.2] — 2026-07-20

### Added

- Coverage tests for v1.0 deprecation shim re-exports (`unplug.core.*`, `guard_scan`, `scanner`, `safeguards`)
- Offline synthetic BIOES checkpoint fixture for ML unit tests (no real weights required)
- CI wheel-only resolve for `unplug-ai[ml]` on Python 3.13 (catches sdist-only breakage)

### Removed

- Dead modules: `providers/scrape.py`, `providers/content/server.py`, `optional/haystack.py` (unused; use `guards/scrape`, `providers/content/firecrawl`, `integrations/haystack`)
- Config fields `judge_enabled`, `pipeline.judge_timeout` (no-op; pass `judge=` to `Guard()` instead)

### Changed

- Unknown `active_model` tier names now raise `ConfigError` with valid catalog tiers instead of silently running without ML
- Widen `transformers` extra constraint to `>=4.44,<6` (was `<5.13`) so newer minors stay installable
- Drop published `dev` optional-extra; test/lint tools live in the `dev` dependency-group (`uv sync --dev`)
- Deprecated config: `judge_enabled`, `pipeline.judge_timeout`, `pipeline.fail_closed` warn and are ignored (removed in v1.0); `guard.fail_closed=false` / `fail_mode="open"` unchanged
- Docs: `unplug-ai[scrape]` package name in Firecrawl docstring; Atomic Agents Python ≥3.12 install gate; Semantic Kernel `pybars4` wheel-only note

### Fixed

- Agent usability: `Guard.init()` docstring no longer claims auto-instrumentation; docs standardize on `from unplug import ...` for apps and `unplug.api.*` for server/MCP dependents; routine `REVIEW` pipeline outcomes log at INFO instead of WARNING
- ML inference hardening: BIOES decode no longer crashes on checkpoints without `*-INJ` labels; label maps are validated at load with a clear `ModelError`; forced torch devices are validated (`ConfigError`); `ModelProvider`/`SpanInferenceModel` load is thread-safe; ML modules log device/tokenizer fallbacks and import torch via `unplug.optional.ml` helpers
- Model store hardening: corrupt manifests no longer crash Guard or `unplug-models`; checkpoint validation requires weight files; atomic manifest writes and download swaps preserve existing installs on failure; `list_status` correctly reports stale revisions as upgrade-available; invalid `UNPLUG_MODEL_PATH` logs a warning; CLI download errors distinguish missing ML extras from network/repo failures

## [0.5.1] — 2026-07-20

### Fixed

- Python 3.13: `unplug-ai[ml]` / `[all]` install without a Rust toolchain — widen `transformers` constraint to `>=4.44,<5.13` so `tokenizers` resolves to a cp313 wheel (was pinned via `transformers>=4.44,<4.45` → `tokenizers==0.19.1`)

### Security

- Pin bundled model catalog to immutable Hugging Face commit SHAs under `Unplug-AI/`; drop unpublished medium/large tiers that pointed at a non-existent org

### Added

- Beginner onboarding: [`sdk/docs/GETTING_STARTED.md`](sdk/docs/GETTING_STARTED.md) (5-minute path)
- Agent-host guide: [`sdk/docs/AGENT_ACTIONS.md`](sdk/docs/AGENT_ACTIONS.md) (ALLOW / REVIEW / BLOCK + `ApprovalProvider`)
- `HookDecision.needs_review` and `HookDecision.is_block` helpers for integration adapters
- Stable public API facades under `unplug.api.*` for policy, privacy, cache,
  boundaries, normalization, encoding, and ML runtime imports used by server/MCP
  dependents ([`sdk/docs/PUBLIC_API.md`](sdk/docs/PUBLIC_API.md))

### Changed

- Integrations hub: pick-your-path table, PyPI doc links, REVIEW vs BLOCK section
- `unplug-audit --probes` skips FP/encoding batteries when ML is inactive (boundary probes still run); clearer CLI hints
- `unplug.example.toml`: ML settings commented by default (regex-only copy-paste safe)
- PyPI `Documentation` URL points to Getting Started; `scan_context_file` tuple examples fixed in READMEs
- `unplug-scan-action` default version pin bumped to `>=0.5.0,<0.6`
- `CONTRIBUTING.md`: full framework extras table

## [0.5.0] — 2026-06-27

### Added

- Integration adapters for seven more agent frameworks: **OpenAI Agents SDK** (`unplug.integrations.openai_agents`, native input/output guardrails), **LangChain** (`unplug.integrations.langchain`, LCEL Runnable guards + a tool-gating callback handler), **Google ADK** (`unplug.integrations.google_adk`, `before_model` / `before_tool` callbacks), **smolagents** (`unplug.integrations.smolagents`, task gate + `final_answer_checks` + tool guard), **DSPy** (`unplug.integrations.dspy`, `unplug_guard_module` wrapping + `dspy_guard_tool` for ReAct), **Strands Agents** (`unplug.integrations.strands`, a `HookProvider` that cancels destructive tool calls), and **Letta** (`unplug.integrations.letta`, client-boundary message/response guards)
- Per-framework optional extras `unplug-ai[openai-agents]`, `[langchain]`, `[google-adk]`, `[smolagents]`, `[dspy]`, `[strands]`, `[letta]`, all folded into the `integrations` meta-extra
- Three more framework adapters: **Griptape** (`unplug.integrations.griptape`, `on_before_run` / `on_after_run` task hooks + tool gate), **AG2** (`unplug.integrations.ag2`, `ConversableAgent` message hooks + `ag2_guard_tool`, distinct from the Microsoft `autogen` extra), and **Atomic Agents** (`unplug.integrations.atomic_agents`, Pydantic IO-schema input/output guards)
- Optional extras `unplug-ai[griptape]`, `[ag2]`, `[atomic-agents]` (the last gated to Python ≥3.12, which the library requires), folded into the `integrations` meta-extra
- Per-framework guides under `integrations/` and runnable demos under `examples/` for each new adapter
- Expanded the agent security matrix from 40 to **72 angles** (ten new framework bindings), plus live tests and dedicated `Integrations (live)` CI legs for each new extra

## [0.4.1] — 2026-06-25

### Added

- Agent-framework integration hub (`unplug.integrations.*`): framework-agnostic `AgentHooks` plus adapters for LangGraph, Agno, CrewAI, AutoGen, LlamaIndex, Pydantic AI, Semantic Kernel, and a custom-loop guide
- Per-framework optional extras (`unplug-ai[langgraph]`, `[agno]`, `[crewai]`, `[autogen]`, `[llama-index]`, `[pydantic-ai]`, `[semantic-kernel]`, `[mcp]`) and an `integrations` meta-extra that installs them all
- 40-angle agent security matrix (`tests/security/test_agent_integration_matrix.py`)
- Live per-framework integration tests (`tests/optional/live/`) behind a dedicated `Integrations (live)` CI job (per-framework matrix, `requires_integrations` marker), with exit-5 tolerance for frameworks that are unimportable under our pinned deps
- Integrations documentation hub under `integrations/` (per-framework guides + `TESTING.md`)

### Changed

- `all` extra now installs capability extras only (`ml,scrape,litellm,yara,haystack,presidio`); agent-framework adapters install via the `integrations` extra (or one at a time) so the core dependency tree and default CI matrix stay lean

## [0.4.0] — 2026-06-24

### Added

- `ScanResult.degraded` and `ScanResult.degraded_layers` — surface when configured protection layers were unavailable
- Token privacy filter (`build_privacy_filter`, `ModelPrivacyFilter`, `HeuristicPrivacyFilter`) behind optional `presidio` / ML extras
- `MIGRATION.md` — API stability tiers, deprecated import paths, and v1.0 removal timeline
- `refresh_scan_result` stable export at `unplug.api.results`
- README benchmark table separating regex-only vs ML recall-gate metrics
- `with_tiny()` recall-gate preset tuned for higher ML recall on injection

### Fixed

- Privacy filter thread-safe model load and `max_length` forwarding
- Benchmark ML guard pipeline isolation and exfil demo output edge cases

### Changed

- Flat `unplug.core.*` shim imports emit `DeprecationWarning`; canonical subpackages are preferred
- `unplug.guard_scan` emits deprecation warning — use `unplug.api.results`
- Judge default model updated to `gpt-5.4-nano`
- Audit remediation bundle (#41–#42): degradation metadata, privacy filter, scan CLI hardening

## [0.3.1] — 2026-06-13

### Added

- `unplug-scan-pr` CLI — scan changed agent/MCP config files in PRs (regex-only Guard)
- GitHub composite action `.github/actions/unplug-scan` and reusable `workflow_call` workflow
- `strict_scanner_allowlist` config — raise `ConfigError` when mandatory input scanners are omitted
- Model cache revision + `config.json` digest verification in `ModelStore`
- Judge sanitization — strip scanner finding evidence before BYOLLM prompts

### Fixed

- `ScanPolicy()` default when `context.scan_policy` is None — USER secret scanning no longer silently disabled
- `ConfigError` from strict allowlist propagates from `Guard.scan_request` (not swallowed by fail-closed)
- `UnplugClient.batch_scan` raises `ServerError` on missing or invalid `results` key
- URL scanner evasion normalize with homoglyph/punycode patterns on raw text

### Changed

- Patch release bundling audit remediation (#27–#29) and Phase B distribution work (#30)

## [0.3.0] — 2026-06-01

### Changed

- **ABSTAIN semantics:** `ScanResult.safe` is `False` for `Action.ABSTAIN` by default; set `policy.abstain_is_safe = true` for legacy pass-through
- **ML gate default:** `always_below_high = false` and `gray_low = 0.3` — use `preset = "recall"` or `always_below_high = true` for max recall
- **Unified thresholds:** input, output, and tool-call pipelines share `ScanPolicy` via `decide_action()`
- **Tool approval:** caller `approved=True` is ignored; use `ApprovalProvider` to clear `REVIEW`
- **Hooks:** non-`ALLOW` actions block; retrieved content returns redacted text, not raw wrapped input
- **Haystack ingest:** `strict_ingest=true` (default) requires `action == ALLOW` and `safe`
- **Config:** `[toolchain]` and `[collusion]` TOML sections load into `GuardConfig`; unknown scanner names fail at init
- **`fail_closed` / `fail_mode="open"`:** deprecated — errors always fail closed

### Added

- `scan_user_secrets` on `ScanPolicy` — USER input scanned for secret-shaped leakage patterns
- `Guard.ml_degraded` when `active_model` is set but ML failed to load
- Pipeline-level normalization cache (one normalize pass per input scan)
- `ServerError`, `ScanPolicy`, `ConfigError` exported from top-level `unplug`
- `src/unplug/py.typed` for PEP 561

### Changed (prior)

- **Tagline:** "Unplug the bad AI" (README, pyproject, package docstring)
- **Canonical namespace:** `unplug.scanners.*` replaces `unplug.safeguards.*`
- **Core layout:** `core/` split into subpackages (`taint/`, `normalize/`, `policy/`, `agent/`, `privacy/`, `runtime/`, `redaction/`) with flat shims until v1.0
- **Patterns externalized:** Regex lists in `data/patterns/*.yaml`; maps in `data/maps/*.toml`; loaded via `core/pattern_loader.py`
- **Optional deps:** Fail-loud `unplug.optional.*` modules replace `is_available()` soft skips
- **YARA rules:** Bundled under `data/yara_rules/`

### Deprecated

- `unplug.safeguards` — import from `unplug.scanners` (removed v1.0)
- `SafeguardRegistry` — use `ScannerRegistry` (removed v1.0)
- Flat `unplug.core.*` shim modules — import from subpackages (removed v1.0)

### Added

- `CODE_OF_CONDUCT.md`, `SECURITY.md` at repo root
- `sdk/docs/ARCHITECTURE.md`, `RESTRUCTURE_PLAN.md`, `LOGIC_AUDIT.md`
- Runtime dependency: `pyyaml`
- `tests/unit/core/test_pattern_loader.py`
- Dev branch workflow; PyPI publish from `main`
- Safeguard registry, ML span model preview, agent hardening suite
