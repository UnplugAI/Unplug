# Changelog

All notable changes to the `unplug-ai` SDK.

## [Unreleased]

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
