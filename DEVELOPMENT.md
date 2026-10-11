# Development

## Environment

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,analysis]'      # add ,scanners for semgrep (+ pip-audit)
export PATH=$PWD/.venv/bin:$PATH
```

Optional external tools: `gitleaks` (binary on PATH), `gh` (GitHub CLI, logged in), `claude` (Claude Code CLI,
logged in). Tests that need a missing tool are skipped, not failed.

## Tests

```bash
GSR_OFFLINE=1 pytest -q                               # offline suite (skips GitHub/network tests)
pytest -q                                             # + tests that clone a public repository through gh
GSR_LIVE_LLM=1 pytest -q tests/test_milestone4.py     # live prompt-injection test (uses your claude login)
python scripts/evaluate.py [--llm]                    # end-to-end metrics on tests/fixtures/vulnapp
python scripts/validate_engines.py contracts|web      # frozen-corpus validation (refuses a modified corpus)
```

Tests keep their databases, clones and configuration roots in temporary directories. A test run may create
an empty `data/logs/` directory in the checkout; `data/` and `workspace/` are git-ignored.

## Environment overrides

`GSR_ROOT` (directory containing `config/`), `GSR_DATA_DIR` (SQLite database, caches), `GSR_WORKSPACE`
(clones). See `.env.example`.

## Extending GSR

* **Scanner**: subclass `scanner.base.Scanner` (`name`, `available()`, `scan()`, optionally `scan_file()` for
  static reproduction) and return normalized `Finding`s.
* **Static validator**: return a `StepResult` from `validation/static.py`; it must not execute target code and
  must not store secret values. Add it to `run_static_steps` and test it.
* **Go bug category**: add it to `BUG_CATEGORIES` (`bugs/model.py`), implement it in `bugs/go_detectors.py`
  with annotated fixtures (`// WANT: <STATUS>` / `// SAFE`), add a reproduction plan in `bugs/reproduction.py`,
  and bump `DETECTOR`.
* **Contracts / web rule**: follow `engines/contract.py` (`EngineFinding`); these engines never emit `CONFIRMED`.

## Notes

* Semgrep ignores `tests/` by default; tests copy fixtures to a temporary directory before scanning.
* Fixtures never contain a real secret; the fake token used by the gitleaks tests is generated at test time.
* Database schema changes go through `storage/database.py` migrations, with a test that upgrades an older schema.
