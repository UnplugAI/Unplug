# Using AI to contribute

We build AI security tooling. We are not going to pretend nobody uses a model.

## The rule

If a model wrote a meaningful part of your patch, say so in the PR description.
One line is enough. "Drafted with Claude Code, I reviewed and tested it" covers it.

Undisclosed AI-generated PRs get closed. Not because the code is bad. Because we
cannot review what you cannot explain, and finding that out three review rounds in
wastes your time more than ours.

Disclosed or not, the bar is identical:

- You ran `cd sdk && make check-ci` and it passed.
- You can answer questions about the diff without going back to the model.
- The change does what the issue asked for, and nothing else.

Meet those and we do not care how the characters got into the file.

## What gets closed on sight

- A PR body that describes the journey rather than the change. We do not need to
  know what you tried first.
- Rewrites of files the issue did not mention.
- Invented benchmark numbers, or claims about detection rates that no test backs up.
  This is a security repo. A confident wrong number is worse here than in most places.
- Tests that assert the implementation instead of the behaviour, added only to make
  a coverage gate pass.

## If you are driving an agent

Point it at the issue, `CONTRIBUTING.md`, and the tests that already cover the area.
Make it run `make check-ci` before it writes the PR body, not after. Most of the
agent PRs we close fail because the agent never ran anything, not because it wrote
bad Python.

Read the diff yourself before you open it. If there is a hunk in there you would
not defend in review, take it out.

## Why we bother saying this

Prompt injection research is downstream of trusting what text claims about itself.
A repo that cannot tell which of its patches were understood by a human has the
same problem its own SDK is meant to solve. We would rather be blunt about it early.

Questions about this policy go in
[Discussions](https://github.com/UnplugAI/Unplug/discussions/categories/q-a).
