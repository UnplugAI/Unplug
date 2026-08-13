# Phase C evaluation notes (2026-07-20)

Bounded re-run of the committed corpora after LimitConfig/Judge public polish and
regex gap closures. ML numbers below are **unchanged** from
[`BENCHMARKS.md`](BENCHMARKS.md) (2026-06-15); only regex-only neuralchemy was
re-measured in this phase.

## Reproduce

```bash
cd sdk
uv sync --all-extras --dev

# Datasets are already under benchmarks/data/. To refresh from Hugging Face:
uv run python -m benchmarks.download --dataset all --out benchmarks/data
# neuralchemy: full train export; microsoft: streaming Phase1 subset (default --limit 5000)

# Smoke (built-in samples)
uv run python -c "
from benchmarks.builtin_samples import ALL_SAMPLES
from benchmarks.evaluate import evaluate, print_report
print_report(evaluate(ALL_SAMPLES, threshold=0.5, isolate_sessions=True))
"

# Regex-only (isolated single-turn)
uv run python -m benchmarks.run benchmarks/data/neuralchemy.jsonl --isolated --format json
uv run python -m benchmarks.run benchmarks/data/microsoft_indirect.jsonl --isolated --limit 2500 --format json

# Regex + ML (requires unplug-tiny; slow / network on first download)
uv run python -m benchmarks.run benchmarks/data/neuralchemy.jsonl --ml --isolated --format json
```

## Results (this run)

| Dataset | Samples | Mode | Precision | Recall | F1 | FPR |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| built-in smoke (`ALL_SAMPLES`) | 31 | regex-only | 0.957 | **1.000** | **0.978** | 0.111* |
| neuralchemy/Prompt-injection-dataset | 4,391 | regex-only | 0.992 | **0.405** | **0.575** | 0.005 |
| microsoft/llmail-inject (Phase1 subset) | 2,500 | regex-only | 1.000 | 0.052 | 0.099 | — |

\*Built-in FPR is dominated by one intentional `benign_input_secret` sample that
must still flag on the leakage path.

### Delta vs prior regex baseline ([`BENCHMARKS.md`](BENCHMARKS.md))

| Dataset | Prior recall | New recall | Prior F1 | New F1 |
| --- | ---: | ---: | ---: | ---: |
| neuralchemy regex-only | 0.393 | **0.405** | 0.563 | **0.575** |
| microsoft regex-only | 0.052 | 0.052 | — | — |

Gap closures that moved the needle (sampled FNs → new patterns):
`ignore_everything_above`, `disregard_the_above`, `instructions_updated_supersede`,
`instruction_override_bracket`, `new_instruction_set`, `admin_priority_commands`,
`delete_system_prompt_fresh`, `academic_policy_bypass`, `assistant_follow_user_only`,
`original_programming_replace`. Also: bidi control chars (U+202A–U+202E,
U+2066–U+2069) stripped in the normalizer zero-width stage.

## Remaining actionable gaps

| Gap | Why regex struggles | Recommended path |
| --- | --- | --- |
| Indirect injection (microsoft ~95% miss) | Natural-language instructions in email/tool bodies | Keep `Guard(model="tiny")` / ML second-pass (prior recall **0.91**) |
| Jailbreak / adversarial paraphrases | Open-ended persona and policy-bypass wording | ML + optional `JudgeProvider` gray band |
| Encoding (ROT13 / hex / URL / Morse) | Documented converter expected gaps | Add decode stages only if product needs them; today tracked in `EXPECTED_GAPS` |
| Crescendo / many-shot | Multi-turn; single-turn eval cannot catch | Trajectory / scenario replay (`benchmarks/scenarios/`) |
| Token smuggling beyond bidi/ZW | Homoglyph + tag coverage exists; novel Unicode planes remain | Expand normalizer maps when new families appear in converter matrix |

## LimitConfig + JudgeProvider

Not scored as dataset metrics. End-to-end wiring verified by
`tests/integration/test_guard_limits.py` and `examples/limits_and_judge_demo.py`.
See [`LIMITS_AND_JUDGE.md`](LIMITS_AND_JUDGE.md).
