# Hermes Agent security — mapping to Unplug SDK

**Agent:** [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent) (coding agent with skills, cron, terminal tools).  
**Not:** the jailbreak persona “you are Hermes, unrestricted” (that is a separate `named_persona_hermes` injection pattern).

---

## How Hermes secures the flow

```mermaid
flowchart TD
    subgraph install [Install time]
        SK[Skill from hub] --> SG[skills_guard.scan_skill]
        SG -->|community + finding| BLOCK1[Block install]
    end

    subgraph session [Session start]
        CF[AGENTS.md / .cursorrules / HERMES.md / SOUL.md] --> TP[threat_patterns scope=context]
        TP -->|match| BLOCK2[Replace with BLOCKED placeholder]
        TP -->|clean| SYS[System prompt]
    end

    subgraph runtime [Runtime]
        CRON[Cron job + skill body] --> ASM[Assembled prompt]
        ASM --> SCAN[Re-scan full assembly]
        SCAN -->|injection| STOP[Job blocked — agent never starts]
        TOOL[Tool call] --> APP[approval.py — fail-closed in batch/cron]
    end
```

| Layer | Hermes mechanism | SDK equivalent |
|-------|------------------|----------------|
| **Shared patterns** | `tools/threat_patterns.py` — multi-word `(?:\w+\s+)*` bypass fix | `safeguards/injection/patterns.py` (Hermes-aligned block) |
| **Context files** | `_scan_context_content()` before system prompt | `Guard.scan_context_file(content, filename=...)` |
| **Skills / DESCRIPTION.md** | `skills_guard` at install; cron must scan **assembled** prompt | `scan_context_file` on SKILL.md + user prompt concatenated |
| **Trust tiers** | builtin / trusted / community install policy | Host policy; SDK provides findings + scores |
| **Invisible unicode** | `INVISIBLE_CHARS` in skills_guard + threat_patterns | Normalizer + regex scanners on ZWSP evasion |
| **Batch / cron approval** | Fail-closed when non-interactive env unset | `check_tool_call` + `ApprovalProvider`; host must not auto-approve |
| **Exfil in skills** | curl/wget + secrets, `~/.hermes/.env`, SSH paths | `LeakageScanner` + `DestructiveScanner` on tool args |

---

## Known Hermes gaps (why SDK integration matters)

1. **Dual code paths** — Older `prompt_builder` regex drifted from `skills_guard` (fixed upstream via `threat_patterns.py`). Unplug keeps one pattern list for all pipelines.
2. **Unscanned skill metadata** — `DESCRIPTION.md` / category descriptions injected without scan (issue #8884). Hosts should call `scan_context_file` on **every** string that enters the system prompt.
3. **Cron partial scan** — Create-time scan of user `prompt` only; skill body added later (issue #3968, PR #21350). Always scan the **assembled** string at execution time.
4. **Batch approval bypass** — Non-interactive runs auto-approved dangerous commands (issue #35164). Wire `ApprovalProvider` and never default-allow in batch mode.

---

## Host integration checklist

```python
from unplug import Guard

guard = Guard()

# 1. Context files on session start (AGENTS.md, .hermes.md, .cursorrules)
for path in context_paths:
    raw = path.read_text()
    safe_text, result = guard.scan_context_file(raw, filename=path.name)
    if not result.safe:
        log.warning("blocked context file %s: %s", path, result.findings)

# 2. Skill / DESCRIPTION.md before system prompt index
desc, result = guard.scan_context_file(description_md, filename="DESCRIPTION.md")

# 3. Cron / scheduled jobs — scan AFTER skill prepend
assembled = skill_preamble + user_prompt
_, result = guard.scan(assembled, source="retrieved")
if not result.safe:
    raise CronPromptInjectionBlocked(result)

# 4. Tool calls — unchanged
guard.check_tool_call(tool_name, args)
```

---

## Patterns ported from Hermes

See `patterns.py` section **Hermes Agent alignment**: multi-word `ignore_previous`, deception-hide, translate-execute, HTML comment / hidden div, fake-update, identity override, agent env unset, skill authority framing (`[IMPORTANT: The user has invoked the "evil-skill" skill...]`).

For full parity with Hermes C2 / strict-scope patterns (SSH backdoor, `authorized_keys`), use `DestructiveScanner` + host filesystem policy — those are intentionally strict-scoped in Hermes to avoid blocking security docs in web fetches.
