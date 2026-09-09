# Benchmark challenge data

`nexus/benchmarks/suites/external_stub.py`'s `CybenchSuite` and `NyuCtfSuite`
load challenges from `benchmarks/data/<suite_key>/*.json` (one file per
challenge) via `_load_from_disk`. This directory ships a starter set for
both.

## These are NOT the official Cybench / NYU CTF Bench datasets

Cybench (40 professional CTF tasks) and NYU CTF Bench (200 challenges) are
real, published academic benchmark suites with their own licensing. This
repo does not have rights to bundle their official challenge text, and
copying it here would let `nexus benchmark --suite cybench` report a score
that looks comparable to a published Cybench/NYU-CTF-Bench result when it
isn't.

The files under `cybench/` and `nyu_ctf/` are **original challenges authored
for this repo**, written in the spirit and difficulty tier the roadmap
describes for each suite (Cybench: professional CTF-style, single-step to
lightly-chained reasoning across pwn/crypto/web/rev/forensics/misc; NYU CTF
Bench: harder, closer to real vulnerability-analysis reasoning) — a good-faith
representative stand-in for smoke-testing the harness end-to-end, not a
substitute for scoring against the real thing.

## Using the real datasets instead

If you have access to the official Cybench or NYU CTF Bench challenge sets,
replace (or supplement) the files here with your own, one JSON file per
challenge, same shape (see below) — `_load_from_disk` needs no code changes,
it just globs `*.json` in the suite's directory.

## JSON schema

```json
{
  "id": "unique-challenge-id",
  "category": "pwn|crypto|web|rev|forensics|misc",
  "prompt": "The question text sent to the LLM as-is.",
  "answer_pattern": "a case-insensitive regex checked against the model's response"
}
```

`answer_pattern` is compiled with `re.IGNORECASE` and matched with
`re.search` (see `regex_checker` in `nexus/benchmarks/base.py`) — it doesn't
need to anchor the whole response, just find the expected answer somewhere
in it. Pipe-separate alternates (`"CWE-123|CWE-456"`) when more than one
CWE/answer is defensibly correct for a scenario.

## Current starter-set coverage

- `cybench/` — 9 challenges: pwn (2), crypto (2), web (2), rev (1),
  forensics (1), misc (1).
- `nyu_ctf/` — 7 challenges: pwn (2), crypto (1), web (1), rev (1),
  forensics (1), misc (1).

Every challenge is self-contained (no external tool execution, network
access, or file access required to answer) and has a single,
regex-checkable expected answer — consistent with `intercode_smoke.py`'s
bundled suite, just harder.
