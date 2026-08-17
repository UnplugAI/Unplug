# Roadmap

Current release: **0.6.0**. This is a direction, not a set of dates. Things move
around. If something here matters to you, say so in
[Discussions](https://github.com/UnplugAI/Unplug/discussions/categories/ideas) and it
moves up.

## Now

**Multi-language detection.** Regex and normalization are tuned for English. Ordinary
non-English input no longer trips the evasion path (#121), but detection recall outside
English is untested and we should not pretend otherwise. Needs a non-English corpus
before it needs new patterns.

**Redaction correctness.** Findings that span more of the input than the actual problem
destroy usable text. #122 and the span scoping in #121 are the same underlying issue
showing up in two places.

**Cache correctness.** The safe-prefix cache is the part of the system most likely to
turn a detection into a miss. #116 and #125 are open.

**Benchmark honesty.** The benign corpus has no hard negatives (#120), so the reported
regex FPR of 0.000 is not measuring what a reader assumes it measures.

## Next

**ML model past preview.** `unplug-tiny-v1` carries the recall numbers in
[BENCHMARKS](docs/BENCHMARKS.md) but is still labelled preview. Getting it out of
preview means latency numbers, a quantized option, and a story for CPU-only hosts.

**Streaming and long documents at scale.** Sliding-window scanning exists. It has not
been measured against documents where the window boundary is the attack.

**Framework coverage that stays true.** There are twenty integration directories under
`sdk/integrations/`, nineteen of them behind their own extra. Keeping
them all working as their upstreams move is a real cost, and some of them probably do
not deserve to stay.

## Later

**Hosted API and MCP.** [unplug-server](https://github.com/UnplugAI/unplug-server) and
[unplug-mcp](https://github.com/UnplugAI/unplug-mcp) exist as separate repos. Neither
is the focus while the SDK is still moving.

**Policy as configuration.** Today policy is mostly code plus `unplug.toml` knobs.
Expressing "this tool may never be called on tainted input" declaratively is the
obvious next shape, and we have not designed it yet.

## Not planned

**Being a content moderation library.** Toxicity, NSFW, and brand safety are somebody
else's problem. Unplug is about text that is trying to change what an agent does.

**Blocking as the default answer.** Span-level redaction is the point. Any feature
whose only outcome is a boolean gets pushed back.

## Where the work is

Issues are the source of truth. Anything labelled
[`good first issue`](https://github.com/UnplugAI/Unplug/labels/good%20first%20issue) or
[`mentored`](https://github.com/UnplugAI/Unplug/labels/mentored) is genuinely available
and genuinely wanted. See [CONTRIBUTING.md](CONTRIBUTING.md).
