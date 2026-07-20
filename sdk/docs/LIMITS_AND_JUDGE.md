# Limits and LLM Judge

`LimitConfig` and `JudgeProvider` are wired into `Guard` end-to-end. Neither is a
silent no-op: limits block before scanners run; an optional judge runs on the
gray risk band (or ML ABSTAIN) when you pass `judge=`.

## LimitConfig

Enforces OWASP LLM10 (unbounded consumption) and tool allow/deny lists (LLM06).

| Check | When | Result |
|-------|------|--------|
| `max_input_chars` / `max_input_tokens` | `scan()` / `scan_request()` / `scan_output*` | `Action.BLOCK`, category `limits` |
| `blocked_tools` / `allowed_tools` | `check_tool_call()` | `Action.BLOCK`, subcategory `tool_blocked` |
| `max_tool_calls_per_session` | `check_tool_call()` after allow/deny | `Action.BLOCK`, subcategory `tool_calls_exceeded` |

### Python

```python
from unplug import Guard, LimitConfig

guard = Guard(
    limits=LimitConfig(
        max_input_chars=8_000,
        max_input_tokens=2_000,  # offline estimate: max(words, chars/4)
        allowed_tools=["read_file", "search"],
        blocked_tools=["run_shell"],
        max_tool_calls_per_session=50,
    )
)

result = guard.scan("x" * 20_000)  # blocked: input_too_long
tool = guard.check_tool_call("run_shell", {"cmd": "ls"})  # blocked: tool_blocked
```

### TOML (`unplug.toml`)

```toml
[limits]
max_input_chars = 8000
# max_input_tokens = 2000
max_tool_calls_per_session = 50
allowed_tools = ["read_file", "search"]
blocked_tools = ["run_shell"]
```

```python
from unplug import Guard, load_config

guard = Guard(config=load_config("unplug.toml"))
```

Tool profile policy (`[tools]`) still applies after `LimitConfig`; a deny in either
layer blocks the call.

## JudgeProvider (BYOLLM)

Optional Stage-3 classifier for borderline cases. Pass any object with
`async def judge(text, context) -> JudgeResult`, or wrap a callable with
`CallableJudge`.

| Knob | Default | Behavior |
|------|---------|----------|
| `judge=` on `Guard()` | `None` | Judge disabled |
| `judge_low` / `judge_high` on `GuardConfig` | `0.3` / `0.8` | Invoke when max scanner score is in `[low, high)` **or** ML emitted ABSTAIN |
| Failures / timeouts | — | Fail closed (`Action.BLOCK`, stage `llm_judge`) |

Judge JSON `action` is authoritative for that finding's contribution to
score-driven policy. Inconsistent score/action pairs are clamped:

| Judge `action` | Score handling |
|----------------|----------------|
| `block` | Raised to at least `block_threshold` so enforcement blocks |
| `review` | Clamped into the review band (`>= review_threshold`, `< redact_threshold`) |
| `allow` | Capped below `review_threshold` so the judge finding alone cannot escalate |

Other scanner findings can still raise the overall action above the judge's
verdict. `judge_enabled` in TOML is **deprecated and ignored**. Provide a real
`judge=` instance in code.

### Python

```python
from unplug import CallableJudge, Guard, GuardConfig

async def my_llm(prompt: str) -> str:
    # Call OpenAI / Anthropic / Ollama / LiteLLM; return JSON:
    # {"action":"block|allow|review","category":"...","score":0.9,"reason":"..."}
    ...

guard = Guard(
    judge=CallableJudge(my_llm, timeout=5.0),
    config=GuardConfig(judge_low=0.3, judge_high=0.8),
)
```

LiteLLM helper (optional extra):

```python
from unplug.judge.litellm_judge import make_litellm_judge

guard = Guard(judge=make_litellm_judge(model="gpt-4o-mini"))
```

### TOML thresholds only

```toml
[guard]
judge_low = 0.3
judge_high = 0.8
# judge= must still be passed in Python — there is no silent built-in LLM
```

## Public imports

| Need | Import |
|------|--------|
| Limits | `from unplug import LimitConfig` or `from unplug.api.limits import LimitConfig` |
| Judge | `from unplug import CallableJudge, JudgeProvider` or `from unplug.api.judge import ...` |

Do not import `unplug.core.judge` / `unplug.core.limits` in new code.

## Demo

```bash
cd sdk
uv run python examples/limits_and_judge_demo.py
```
