# Getting help

## I have a question about using Unplug

[Discussions → Q&A](https://github.com/UnplugAI/Unplug/discussions/categories/q-a).

Include the version (`pip show unplug-ai`), the code you ran, and what you got back.
For detection questions, paste the `ScanResult`: the action, the risk score, and the
finding IDs. Those three tell us more than a description of the behaviour will.

## Something is broken

[Open a bug report](https://github.com/UnplugAI/Unplug/issues/new?template=bug_report.yml).
A snippet we can paste into a REPL is worth a lot more than a stack trace alone.

## Detection is wrong

False positives and false negatives are bugs, so file them as bugs. Give us the exact
input string. If it contains anything you cannot share, a minimised version that still
reproduces is fine.

Before filing, check whether your input is non-English. Regex detection is tuned for
English today and we track that separately, see the language note in the README.

## I found a vulnerability

Do not open an issue.
[Report it privately](https://github.com/UnplugAI/Unplug/security/advisories/new).
See [SECURITY.md](SECURITY.md).

## I want to contribute

[CONTRIBUTING.md](CONTRIBUTING.md), and read
[the claiming rules](CONTRIBUTING.md#claiming-an-issue) before you write code.

If you are new to open source, look for the
[`mentored`](https://github.com/UnplugAI/Unplug/labels/mentored) label. Those issues
come with a maintainer who will walk you through it.

## Response times

This is a small project. Issues and Discussions usually get a reply within a day or
two. Security reports get looked at faster. If something has been quiet for a week,
bump the thread. That is not rude, we probably missed it.
