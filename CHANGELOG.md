# Changelog

All notable changes to the `unplug-ai` SDK.

## [Unreleased]

### Added

- Integration adapters for four more agent frameworks: **OpenAI Agents SDK** (`unplug.integrations.openai_agents`, native input/output guardrails), **LangChain** (`unplug.integrations.langchain`, LCEL Runnable guards + a tool-gating callback handler), **Google ADK** (`unplug.integrations.google_adk`, `before_model` / `before_tool` callbacks), and **smolagents** (`unplug.integrations.smolagents`, task gate + `final_answer_checks` + tool guard)
- Per-framework optional extras `unplug-ai[openai-agents]`, `[langchain]`, `[google-adk]`, `[smolagents]`, all folded into the `integrations` meta-extra
- Per-framework guides under `integrations/` and runnable demos under `examples/` for each new adapter
- Expanded the agent security matrix from 40 to **52 angles** (new framework bindings), plus live tests and dedicated `Integrations (live)` CI legs for each new extra

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
