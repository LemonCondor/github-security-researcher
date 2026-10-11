# Contributing

Thank you for helping. GSR values precision over volume: a small, well-tested change is better than a large one.

## Before you start

* Read [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
* For anything beyond a small fix, open an issue first to discuss the approach.
* Security problems in GSR itself: report them privately (SECURITY.md), not in an issue.

## Development setup

See [DEVELOPMENT.md](DEVELOPMENT.md). The offline suite must pass: `GSR_OFFLINE=1 pytest -q`.

## Rules for changes

* Every change ships with tests.
* Precision first: a new rule, detector or validator comes with a true-positive **and** a false-positive trap in
  `tests/fixtures/`, and must not degrade `scripts/evaluate.py` or the frozen validation corpora
  (`scripts/validate_engines.py`). Never edit a frozen corpus to make a rule pass.
* A change to the Go bug detector bumps `DETECTOR` in `bugs/storage.py` (it keys caches and reconciliation).
* Never add code that executes target-repository code, contacts target infrastructure, or sends
  disclosures, PRs, issues or comments without the explicit policy gates in `security/policy.py`.
* The decision engine stays deterministic and independent of LLM free text: LLM output may only add
  `ADVISORY` evidence. Do not add a path from LLM output to `CONFIRMED`.
* Never log or persist secret values; route new outputs through `security.secrets.redact`.
* Test fixtures must stay synthetic. Secret-like strings must be obviously fake (e.g. contain `Fixture` or
  `NotAReal`) and live under `tests/fixtures/`.
* Keep patches minimal; no drive-by refactors.

## Pull requests

* Describe the problem, the change, and how you tested it (commands and results).
* If an AI tool helped write code, tests or text, say what it did; you remain responsible for every line.
* By contributing you agree that your contribution is licensed under the Apache License 2.0 (see LICENSE).
