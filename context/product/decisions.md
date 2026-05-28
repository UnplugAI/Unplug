# Decisions

## 2026-05-09: Project name and positioning
- Name: **Unplug** ("Pull the plug on bad AI")
- Positioning: LLM defense layer, not just prompt injection
- Verticals: injection, destructive actions, leakage, harmful output
- License: Apache 2.0

## 2026-05-09: Architecture — SDK + Server
- SDK-first: works standalone without the server
- Server: FastAPI, self-hosted, same engine as SDK
- MCP server: planned for distribution
- Models loaded in FastAPI lifespan, not per-request

## 2026-05-09: Redaction over blocking
- Default action is span-level redaction, not binary blocking
- Every finding includes span offsets and evidence
- Preserves legitimate content while stripping malicious parts

## 2026-05-09: Model choice
- Start with off-the-shelf ProtectAI DeBERTa (proven, Apache 2.0)
- Evaluate Sentinel (ModernBERT-large, 98.7% accuracy) as upgrade
- Fine-tune only after benchmarking shows gaps
- ONNX for cross-platform inference

## 2026-05-09: Adoption strategy
- Don't sell "security" — sell "LLM testing and hardening"
- Three distribution surfaces: SDK, MCP server, GitHub Action
- Auto-instrument pattern (Guard.init()) for zero-config adoption
- Insurance partnership angle: Corgi/Klaimee for enterprise adoption

## 2026-05-11: Positioning pivot (post-review)
- **Old framing**: "We detect prompt injections and bad actions"
- **New framing**: "We create an enforcement layer between LLM reasoning and real-world execution"
- This is a category, not a feature. Framework-agnostic, centrally managed.
- We are NOT a LangChain plugin. We are the runtime policy layer across all agent systems.

## 2026-05-11: Moat clarification (post-review)
- "Adoption friction" is NOT a moat. Distribution advantage ≠ moat.
- Real moat: **threat intelligence data flywheel** — every scan improves detection, cross-framework telemetry sees attacks no single framework can
- Technical depth: **taint tracking** (data provenance across agent execution) + **intent verification** (does the action match the user's original intent?)
- These are genuinely hard problems OpenAI won't casually ship next quarter

## 2026-05-11: Pitch discipline (post-review)
- No latency claims until we have real benchmarks
- No acquisition name-dropping unless asked and verified
- No insurance/compliance/EU AI Act in core pitch — these are context, not the pitch
- One sharp wedge: "runtime security for AI agents"
- Insurance = long-term opportunity, not core identity

## 2026-05-11: Technical differentiation needed
- 4 regex scanners alone feel commodity ("couldn't I assemble this?")
- Must build genuinely hard technical features:
  1. Taint tracking across execution graphs (data provenance)
  2. Semantic intent verification before tool execution
  3. Dynamic risk scoring across agent trajectories (catches crescendo attacks)
- These move us from "prompt injection scanner" to "agent runtime security platform"

## 2026-05-28: OpenClaw agent hardening wired into SDK
- **Boundaries:** `auto_wrap_untrusted` on `RETRIEVED` / `TOOL_OUTPUT` in `InputPipeline`; public `Guard.wrap_for_context()`
- **Session policy:** existing CaMeL-lite taint + tool profiles unchanged; now complemented by trajectory + intent gates
- **Crescendo:** `TrajectoryConfig` — escalating `risk_trajectory` slope → REVIEW/BLOCK findings on all pipelines
- **Intent:** `IntentConfig` — informational user intent + side-effect tool → REVIEW
- **Hermes/persona:** named persona + red-team regex patterns in injection scanner
- **Out of SDK scope:** container sandbox, channel pairing, filesystem/network egress (host responsibility)
- **Detail:** `.context/research/openclaw-agent-security.md`

- **Question:** Use Microsoft Presidio to filter agent-exposed PII?
- **Answer:** Useful as optional server-side benchmark / interim `PrivacyFilterService` backend only — not a replacement for Unplug or the planned unplug-safeguard PF head.
- **Already covered:** `LeakageScanner` regex (email, phone, SSN, keys) + output pipeline span redaction + `ScanPolicy` coverage BLOCK.
- **Presidio adds:** names, addresses, international/custom entities — where regex under-recalls.
- **Does not add:** injection, destructive tools, taint, fail-closed guard architecture.
- **Production path unchanged:** unplug-safeguard Privacy Filter on server (see span-pipeline spec Stage 3).
- **Detail:** `.context/research/presidio-pii.md`
