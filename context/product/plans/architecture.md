# Unplug Architecture Plan

## Context

Building an LLM defense layer that stops prompt injection, destructive agent actions, data leakage, and harmful output. Two components: Python SDK (pip install) + FastAPI server (self-hosted API). Distribution also via MCP server and GitHub Action.

## 3-Stage Detection Pipeline

> Status legend: [implemented] ships today · [planned] designed, not built · [target] a goal with a current measured number, not a claim. All metrics come from the golden eval harness (`unplug_exp/scripts/golden_eval.py`) — see `BENCHMARKS.md`. No hand-typed numbers.

```
Stage 1: Regex + Heuristics (<1ms)  [implemented]
├── 12 normalization stages (leetspeak, zero-width, homoglyphs, base64, etc.)
├── 29 injection patterns (English) + destructive/leakage/harmful/financial scanners
│     (regex alone is a sub-millisecond pre-filter, NOT a standalone product)
├── Produces span offsets of suspicious regions
└── High-confidence → short-circuit, return immediately

Stage 2: ML Classifier (5-15ms)  [implemented: transformers · planned: ONNX export]
├── DeBERTa-v3-xsmall dual-head (doc classifier + token/BIOES span tagger)
├── Runs via the optional ml extra (transformers today; ONNX/INT8 export planned)
├── Loaded once, reused across requests
└── Doc head → detection recall; token head → span localization / redaction

Stage 3: LLM Judge (500ms-2s, ~5% of requests)  [planned]
├── BYOLLM JudgeProvider (CallableJudge), disabled by default
├── Structured reasoning on the ~5% ambiguous middle band
└── Hard negative mining: confirmed benign → feed back to Stage 2
```

## Scanner Modules

### 1. Injection Scanner (injection.py)
- Prompt injection, jailbreaks, role hijacking
- Indirect injection in documents/tool results
- System prompt extraction attempts
- Encoding evasion (base64, unicode, leetspeak)

### 2. Destructive Action Scanner (destructive.py)
- SQL: DROP, DELETE, TRUNCATE, ALTER without safeguards
- Shell: rm -rf, kill, shutdown, format
- File: unlink, rmdir, os.remove patterns
- API: DELETE endpoints, destructive HTTP methods
- Agent tool calls that modify/delete resources

### 3. Leakage Scanner (leakage.py)
- API keys, tokens, passwords in output
- PII detection (email, phone, SSN patterns)
- System prompt leakage
- Internal URL/path exposure
- Training data regurgitation signals

### 4. Harmful Output Scanner (harmful.py)
- Toxic/hateful content classification
- Dangerous instructions (weapons, drugs, self-harm)
- Biased or discriminatory output
- Configurable policy rules

## SDK Architecture

```python
# Public API
from unplug import Guard

guard = Guard(
    scanners=["injection", "destructive", "leakage", "harmful"],
    mode="local",           # or "server" for HTTP mode
    server_url=None,        # set when mode="server"
    fail_mode="closed",     # block on errors
    log_findings=True,
)

result = guard.scan(text, source="user")
# result.safe -> bool
# result.action -> "allow" | "redact" | "block" | "review"
# result.risk_score -> float
# result.findings -> list[Finding]
# result.redacted_text -> str | None

# Auto-instrument frameworks
Guard.init()  # patches LangChain, CrewAI, etc.
```

### Models (Pydantic)

```python
class Source(str, Enum):
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    SYSTEM = "system"

class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REVIEW = "review"

class Finding:
    category: str          # "injection", "destructive", "leakage", "harmful"
    subcategory: str       # "role_override", "sql_drop", "api_key", etc.
    stage: str             # "regex", "classifier", "llm_judge"
    span_start: int
    span_end: int
    score: float
    evidence: str
    replacement: str | None

class ScanResult:
    safe: bool
    action: Action
    risk_score: float
    findings: list[Finding]
    redacted_text: str | None
    latency_ms: float
    stages_run: list[str]
```

## Server Architecture

```
FastAPI App (lifespan loads models)
├── POST /v1/scan          # Scan text, return findings
├── POST /v1/redact        # Scan + return redacted text
├── POST /v1/batch         # Batch scan multiple texts
├── GET  /v1/health        # Health check
└── GET  /v1/stats         # Scan statistics

Layering:
  Routes → Services → Scanners
  (same pattern as crabgrass-backend)

Services:
  DefenseOrchestrator
  ├── RegexEngine (sync, threadpool)
  ├── ClassifierService (ONNX, threadpool)
  └── LLMJudge (optional, async)
```

## Performance Targets

| Metric | Target |
|--------|--------|
| Stage 1 (regex) | <1ms |
| Stage 2 (classifier) | <15ms |
| Stage 3 (LLM judge) | <2s, only 5% of requests |
| Overall p50 | <20ms |
| Overall p99 | <50ms (excluding Stage 3) |
| Memory | <500MB (ONNX model + tokenizer) |

## Implementation Order

1. SDK core: Guard class, Scanner protocol, Finding/ScanResult models
2. Regex engine: normalization + pattern matching + span mapping
3. Injection scanner: regex patterns for all 29 attack categories
4. Destructive scanner: SQL/shell/file/API patterns
5. Server: FastAPI app, /v1/scan endpoint, lifespan model loading
6. Classifier: ONNX integration with ProtectAI DeBERTa (off-the-shelf first)
7. Leakage scanner: API key, PII, system prompt patterns
8. Harmful scanner: output policy rules
9. Auto-instrument: LangChain/CrewAI/LlamaIndex patches
10. Benchmarks: accuracy + latency on public datasets
11. MCP server: distribute as MCP tool
12. Fine-tune: train own model only after benchmarking shows gaps
