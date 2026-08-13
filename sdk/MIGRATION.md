# Migration & deprecation guide

This documents deprecated import paths and APIs, the canonical replacement, and
when each will be removed. Deprecated paths keep working until the listed removal
version so you can migrate on your own schedule.

## API stability tiers

`import unplug` exposes three tiers. Depend freely on **Stable**; pin a version
before depending on **Provisional**; treat **Internal** as private (it can change
in any release).

| Tier | Symbols | Guarantee |
|------|---------|-----------|
| **Stable** | `Guard`, `GuardConfig`, `TaintedText`, `TrustLevel`, `Source`, `Finding`, `ScanResult`, `Action`, `ScanPolicy`, `SecretsRegistry`, `ExecutionContext`, `ToolCall`, `UnplugClient`, `load_config`, exceptions (`ConfigError`, `ServerError`) | No breaking changes within a major version |
| **Provisional** | `ModelProvider`, `ModelRegistry`, `ModelSpec`, `PipelineConfig`, `ThresholdConfig`, `MessageConfig`, `LimitConfig`, `CallableJudge`, `JudgeProvider`, `JudgeContext`, `JudgeResult`, `ScannerConfig`, `MetricsCollector`, `correlation_scope`, `get_correlation_id` | May change with a minor-version note |
| **Internal** | `BaseScanner`, `ModelScanner`, `RegexScanner`, `Tagger`, `SafeguardRegistry`, anything under `unplug.core.*`, `unplug.guard_scan` | No stability guarantee — import at your own risk |

## Deprecated paths (removed in v1.0)

| Deprecated | Use instead | Notes |
|------------|-------------|-------|
| `unplug.safeguards.*` | `unplug.scanners.*` | `scanners/` is canonical; `safeguards/` is a shim |
| `SafeguardRegistry` | `ScannerRegistry` | alias kept importable from top level |
| `unplug.scanner` (module) | `unplug.scanners` | |
| Flat `unplug.core.<name>` shims (e.g. `core.canary`, `core.cache`, `core.intent`, `core.encodings`, …) | their subpackage home (e.g. `core.agent.canary`, `core.runtime.cache`, `core.agent.intent`, `core.normalize.encodings`) | ~25 modules re-export from subpackages (note: `core.taint`, `core.policy`, `core.privacy`, `core.normalize` are canonical subpackages, **not** shims) |
| `unplug.guard_scan` | `unplug.api.results` | `refresh_scan_result` now lives in `api.results`; `guard_scan` is a back-compat shim that emits a `DeprecationWarning` |
| `fail_closed=false` / `fail_mode="open"` | (removed) | errors always fail closed; the flag is ignored |
| `judge_enabled` | `judge=` on `Guard()` | config flag was a no-op without a provider; removed in v1.0 |
| `pipeline.judge_timeout` | (removed) | never wired; removed in v1.0 |
| `pipeline.fail_closed` | (removed) | duplicate of deprecated `guard.fail_closed`; removed in v1.0 |
| `Guard.with_tiny(...)` | `Guard(model="tiny", ...)` | emits a `DeprecationWarning`; produces an identical config. `auto_download` is now `auto_download_model` |

## Notes / known follow-ups

- **Model selection is now one argument.** `Guard(model="tiny")` replaces
  `Guard.with_tiny()`, so adding a tier does not add a constructor. Gate tuning
  moved with it: each tier declares its recommended `pipeline.ml_gate` under
  `[catalog.tiers.<tier>.gate]` in `data/catalog.toml`, applied only when the
  caller has not set one. Previously `with_tiny()` hardcoded the recall gate while
  `active_model="tiny"` silently got the weaker default, which the docs described
  as equivalent. They now genuinely are.

- **`refresh_scan_result`** now has a stable home at `unplug.api.results`. The old
  `unplug.guard_scan` path still works (back-compat shim, emits a `DeprecationWarning`).
  `unplug-server` imports it from `guard_scan`; that import moves to `api.results`
  **after the next SDK release** (the server installs the published SDK, which must
  contain `api.results` first).
- The flat `core.*` shims now emit a `DeprecationWarning` on import. SDK-internal
  code uses the canonical subpackages, so normal use (`import unplug; Guard()`)
  emits no warning. `unplug-server`/`unplug-mcp` are migrated off the few flat shims
  they used (`core.boundaries`, `core.cache`, `core.encodings`, `core.versions`) in
  lockstep. The canonical subpackages (`core.taint`, `core.policy`, `core.privacy`,
  `core.normalize`, `core.agent`, `core.runtime`, `core.context`) are **not** shims.

## Removal timeline

- **v0.x:** deprecated paths work; this guide tracks them.
- **v1.0:** all paths in the table above are removed. Migrate before upgrading to v1.0.
