# GitHub Security Researcher (GSR)

A local, policy-gated toolkit for **security and bug research on public open source code**.
GSR scans repositories you have explicitly put in scope, stores every finding in a local SQLite database,
gathers typed evidence about each one, and lets a **deterministic decision engine** (not an LLM) decide
whether a finding is `CONFIRMED`, `FALSE_POSITIVE` or `INCONCLUSIVE`.

> **LLM analysis alone cannot produce CONFIRMED.**
> The LLM proposes; independent, verified evidence decides. In doubt, the verdict is `INCONCLUSIVE`.

Principles: precision over quantity · reproducibility over claims · security over automation ·
minimal patch over large refactor · real findings over false positives.

GSR does **not** guarantee that it finds every vulnerability, and it does **not** guarantee the absence of
false positives. It is a research aid that keeps a human in charge of every decision that leaves the machine.

## Results

Real bugs found with GSR (or with the fuzzing and property tests built alongside it), each reproduced by a failing
test, fixed with a minimal patch and a regression test, and submitted under each project's contribution rules.
These are functional and robustness bugs, not security vulnerabilities.

| Project | Fix | Status (2026-10-11) |
|---|---|---|
| Kubernetes git-sync | panic on a git config key without a value — [#1006](https://github.com/kubernetes/git-sync/pull/1006) | merged |
| Google gVisor | ignored lock error in `Container.Update` — [#15632](https://github.com/google/gvisor/pull/15632) | approved |
| Canonical LXD | User-Agent parser panic — [#19250](https://github.com/canonical/lxd/pull/19250) | approved |
| NASA F´ (fprime-tools) | auto-merge rejected valid C++ — [issue #6176](https://github.com/nasa/fprime/issues/6176), [#356](https://github.com/nasa/fprime-tools/pull/356) | in review |
| data.gouv.fr (udata) | undashed dates parsed as a whole year — [#4007](https://github.com/opendatateam/udata/pull/4007) | in review |
| Prometheus node_exporter, procfs, mysqld_exporter | `/proc` and binlog parsers — [#3848](https://github.com/prometheus/node_exporter/pull/3848), [#880](https://github.com/prometheus/procfs/pull/880), [#1095](https://github.com/prometheus/mysqld_exporter/pull/1095) | in review |
| Google cAdvisor, Kubernetes kube-state-metrics | [#3947](https://github.com/google/cadvisor/pull/3947), [#3143](https://github.com/kubernetes/kube-state-metrics/pull/3143) | in review |

## Contents

1. [The problem](#the-problem)
2. [Goals and scope](#goals-and-scope)
3. [What is implemented](#what-is-implemented)
4. [Architecture](#architecture)
5. [Analysis and validation pipeline](#analysis-and-validation-pipeline)
6. [Engines and their limits](#engines-and-their-limits)
7. [Requirements and installation](#requirements-and-installation)
8. [Configuration](#configuration)
9. [CLI commands](#cli-commands)
10. [Reproducible example](#reproducible-example)
11. [Expected results](#expected-results)
12. [Tests](#tests)
13. [Known limitations](#known-limitations)
14. [Security rules](#security-rules)
15. [Contributing](#contributing)
16. [License](#license)
17. [Roadmap](#roadmap)

## The problem

Static analyzers and LLM reviewers produce many plausible-looking alerts. Most are false positives, and an
LLM can be confidently wrong or manipulated by text planted in the code it reads. Reporting such alerts wastes
maintainers' time; acting on them automatically (opening PRs or issues, testing live systems) can cause harm.

GSR addresses this by separating **detection**, **contextual analysis**, **evidence** and **decision**, by
treating every repository file as untrusted data, and by refusing to act outside an explicit scope.

## Goals and scope

* Find real, reproducible defects in public code: security findings (secrets, injection-style dataflows,
  vulnerable dependencies) and ordinary bugs (Go parsing and error-handling defects).
* Keep a durable, auditable record: what was detected, what the LLM said, which evidence exists, and why the
  engine decided what it decided.
* Stay inside an authorized scope: only repositories listed in `config/targets.yaml` are cloned or scanned.
* Never disclose anything automatically. Reports and PR drafts are prepared locally and sent by a human,
  through the channel required by the project's security policy.

Out of scope: testing live infrastructure, exploitation, executing code from target repositories, and any
automated outreach (PRs, issues, comments).

## What is implemented

| Area | Status |
|---|---|
| Scope and policy gates (`config/targets.yaml`, `config/policies.yaml`) | implemented |
| Hardened cloning of in-scope public repositories (no hooks, no submodules, no LFS, size cap) | implemented |
| Scanners: semgrep (internal taint rules + optional registry packs), gitleaks, OSV dependency scan, Go dataflow | implemented (semgrep and gitleaks are optional external tools) |
| Contextual LLM review through the local `claude` CLI, without tools | implemented, optional |
| Typed evidence + deterministic decision engine (rules R1–R5) | implemented |
| Ordinary Go bug candidates (`bugs.go` detector) with lifecycle, reconciliation and PR gate | implemented (static, report only) |
| Solidity analysis of local files (`contracts.solidity`) | implemented, preliminary |
| Passive web analysis of local captures (`web.passive`), no network | implemented, preliminary |
| Read-only discovery and ranking of organisations' public repositories | implemented |
| Dynamic validation (executing target code in a sandbox) | **not implemented** (see [Known limitations](#known-limitations)) |
| Automatic PR / issue / comment creation | **not implemented by design**; switches exist and default to `false` |

## Architecture

```
src/github_security/
  cli.py                  argparse CLI (`github-sec`)
  config.py               trusted configuration (targets, policies, organisations)
  pipeline.py             scan → store → review → validate → decide
  github/                 GitHub API through the `gh` CLI; hardened clones
  scanner/                semgrep, gitleaks, OSV, Go dataflow → normalized findings
  analysis/               findings + fingerprints, bounded context, evidence, decision engine, Go dataflow
  ai/                     trusted prompts, LLM reviewer (claude -p, no tools), UNEXECUTED test drafts
  validation/             static validators (never execute target code)
  bugs/                   Go bug detectors, reproduction plans, lifecycle store, PR gate
  contracts/              Solidity engine (tree-sitter-solidity)
  web/                    passive web engine (stdlib only, no fetcher)
  engines/contract.py     common EngineFinding contract for the contracts and web engines
  discovery/              read-only organisation/repository discovery and ranking
  security/               secret redaction, policy gates
  storage/database.py     SQLite schema and migrations
rules/semgrep/            internal high-precision taint rules
scripts/                  evaluation and triage helpers
tests/                    pytest suite and synthetic fixtures
```

Details (data model, fingerprints, evidence types, decision rules, migrations): [ARCHITECTURE.md](ARCHITECTURE.md).

## Analysis and validation pipeline

```
SCANNER → CANDIDATE → CONTEXTUAL_ANALYSIS → EVIDENCE_ASSESSMENT → DECISION_ENGINE
                       (LLM, advisory)        (typed evidence)      (deterministic rules)
        → CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE           (+ a separate confidence score)
```

* Exactly three final verdicts. A high confidence score never makes a finding `CONFIRMED`.
* `CONFIRMED` requires independent, verified evidence that meets the category's proof criteria. Today only
  committed provider-format credentials and private keys can reach it; code findings stay `INCONCLUSIVE`
  because no validator executes code. This is intended.
* The engine reads enums and booleans only, never free text. LLM reasoning is stored as `ADVISORY` evidence
  and can neither confirm nor dismiss a finding on its own.
* `github-sec analyze` runs the static steps first and skips the LLM when its answer could not change the
  decision.
* LLM-written regression tests are stored as **UNEXECUTED drafts**, never as evidence.
* `CONFIRMED` and `INCONCLUSIVE` findings go to a human review queue. Nothing is sent anywhere.

The ordinary-bug pipeline (`github-sec bugs`) is separate from security findings: candidates are classified
`BUG_CANDIDATE` / `NEEDS_REVIEW` / `FALSE_POSITIVE` with the proof of any guard that suppressed them, then
tracked through validation, reproduction, regression test, patch and (human) PR outcome.

## Engines and their limits

| Engine | Input | Finds | Main limits |
|---|---|---|---|
| semgrep (internal rules) | Python sources | HTTP-request data flowing to SQL, shell, eval and similar sinks | needs `semgrep`; intra-file taint only |
| gitleaks | repository files | committed credentials (values redacted) | needs `gitleaks`; liveness is never tested |
| OSV | lockfiles (parsed, never installed) | known-vulnerable dependencies | queries the OSV API; reachability is approximate |
| go_dataflow | Go sources (tree-sitter) | `*http.Request` data reaching sensitive calls | syntactic, intra-module; no type checker |
| bugs.go | Go sources (tree-sitter) | ignored / overwritten errors, unchecked split and regexp-submatch indexes, nil checked before err | static; closures, pointer writes and some loop shapes are not modelled |
| contracts.solidity | local `.sol` files | reentrancy (CEI), access control, tx.origin, unprotected init, unchecked calls, delegatecall, arithmetic | no compiler, no chain; economic logic and proxy layouts out of scope |
| web.passive | local HTTP captures, HTML, JS | headers, cookies, redirects, CORS, disclosure, known JS libraries, secret-like strings | never sends a request; no live phase |

The contracts and web engines were measured on small, frozen, independently labelled corpora
(`tests/fixtures/validation/`). Those numbers are preliminary and are not a precision claim for real code.

## Requirements and installation

Required: Python ≥ 3.11 and `git`.

```bash
git clone <this repository> && cd github-security-researcher
python3 -m venv .venv
.venv/bin/pip install -e '.[dev,analysis]'      # core + tests + tree-sitter engines
```

Optional tools (each feature degrades gracefully and the related tests are skipped when a tool is missing):

| Tool | Used for | Install |
|---|---|---|
| `semgrep` | semgrep scanner | `.venv/bin/pip install -e '.[scanners]'` |
| `gitleaks` | secret scanner | binary from <https://github.com/gitleaks/gitleaks/releases>, on `PATH` |
| `gh` | GitHub metadata, cloning checks, discovery | <https://cli.github.com>, then `gh auth login` (the token stays inside `gh`) |
| `claude` | contextual LLM review and test drafts | Claude Code CLI with an existing login; no API key is read by GSR |

`github-sec status` reports which tools, logins and policy switches are active.

## Configuration

| File | Purpose |
|---|---|
| `config/targets.yaml` | the only scan scope. Empty by default. Each third-party target must cite the published policy (`policy_reference`) that authorizes research; `blocked_targets` always wins. |
| `config/policies.yaml` | global switches (`allow_pr_creation`, `allow_issue_creation`, `allow_comment_creation`, all `false`), scanners, clone limits, LLM settings |
| `config/organizations.yaml` | organisations whose public metadata `github-sec discover` may collect (read-only) |
| `.env.example` | environment overrides (`GSR_ROOT`, `GSR_DATA_DIR`, `GSR_WORKSPACE`); no secrets are needed |

Runtime data is written to `data/` (SQLite database, caches) and `workspace/` (clones). Both are git-ignored.

## CLI commands

```bash
github-sec status                        # tools, GitHub login, policy switches
github-sec config                        # effective configuration
github-sec check-target OWNER/REPO       # read-only metadata: visibility, SECURITY.md, private reporting
github-sec clone OWNER/REPO              # only if listed in config/targets.yaml
github-sec scan OWNER/REPO [--with-bugs] # clone + scanners → SQLite (report only)
github-sec scan --path DIR               # scan a local directory (fixtures, your own code)
github-sec findings [--repo R]           # stored findings and current verdicts
github-sec finding ID [--json]           # detection, LLM analysis, evidence, confidence, decision
github-sec analyze [ID | --repo R]       # full pipeline with pre-LLM static triage (recommended)
github-sec review [ID | --repo R]        # LLM contextual review only
github-sec validate [ID | --repo R]      # static validation + verdict
github-sec draft-test ID                 # LLM regression-test draft (UNEXECUTED)
github-sec review-queue                  # findings awaiting human review
github-sec metrics [--repo R]

github-sec bugs [OWNER/REPO | --path DIR] [--review N]   # ordinary Go bug candidates
github-sec bug ID                        # one candidate: lifecycle, reproduction task, PR gate
github-sec bug-reject REPO ID --reason … # record a reasoned human rejection
github-sec bug-pr REPO ID --event … --url …   # record the real outcome of a PR (nothing is sent)
github-sec bug-metrics [--repo R]        # funnel: candidate → validated → test → patch → PR → merge

github-sec contracts scan PATH [--json]  # local Solidity analysis
github-sec web analyze PATH [--json]     # passive analysis of local web captures
github-sec discover {orgs,refresh,shortlist,show,approve,reject,…}   # read-only discovery
```

Helper scripts: `scripts/evaluate.py` (end-to-end metrics on the synthetic app), `scripts/validate_engines.py`
(frozen-corpus validation of the contracts and web engines), `scripts/hunt.py` (ranked, cached triage of Go bug
candidates in a local checkout), `scripts/dupcheck.py` (read-only duplicate check before preparing an upstream fix).

## Reproducible example

These commands use only the bundled synthetic fixtures; nothing is cloned. The first three are fully local.
`scan` also queries the public OSV API (`api.osv.dev`) for the fixture's dependency lockfile.

```bash
export PATH=$PWD/.venv/bin:$PATH
github-sec bugs --path tests/fixtures/bugs/split_guards      # Go bug candidates with guard proofs (local)
github-sec contracts scan tests/fixtures/contracts            # Solidity findings (local)
github-sec web analyze tests/fixtures/web/pos                 # passive web findings (local)
github-sec scan --path tests/fixtures/vulnapp                 # OSV, plus semgrep/gitleaks when installed
github-sec validate --repo local:vulnapp                      # static evidence + decision, no LLM
github-sec analyze --repo local:vulnapp                       # same with LLM review (needs the claude CLI)
```

Without the `claude` CLI, `analyze` reports `claude CLI not found` for findings that static triage cannot
decide; use `validate` instead.

## Expected results

* `bugs`: each candidate shows its category, status (`BUG_CANDIDATE` / `NEEDS_REVIEW`), the suspicious line and,
  for suppressed ones, the guard that proves the access safe.
* `contracts` and `web`: `EngineFinding` records with location, rule, status (`OBSERVATION`, `CANDIDATE`,
  `NEEDS_REVIEW`, `FALSE_POSITIVE`) and limitations. These engines never emit `CONFIRMED`.
* `validate` / `analyze`: one decision per finding with its rule (`R1`…`R5`), the evidence it used, and a
  confidence score reported separately from the verdict. On the fixture without semgrep, gitleaks or claude, the
  OSV findings end `INCONCLUSIVE` (`R5_INSUFFICIENT_EVIDENCE`) and wait in the human review queue.

## Tests

```bash
GSR_OFFLINE=1 .venv/bin/pytest -q          # GSR_OFFLINE (tests only) skips the tests that need the network
```

Verified on 2026-10-11 from a clean virtual environment (`.[dev,analysis]`, no semgrep, gitleaks, gh or claude):
500 passed, 8 skipped (tests that need the missing tools or the network), no network access attempted.
With semgrep and gitleaks installed, the scanner tests run as well.
`GSR_LIVE_LLM=1` enables the live prompt-injection test against the local `claude` CLI.

## Known limitations

* No dynamic validation: target code is never executed, so code findings cannot reach `CONFIRMED`.
* Go analysis is syntactic (tree-sitter), without type information; some patterns are approximated and are
  documented in the detectors.
* The contracts and web engines are young; their published metrics come from small corpora.
* Discovery and OSV lookups use public APIs and are subject to rate limits.
* A file rename creates a new finding fingerprint.
* Developed and tested mainly on Linux (including an ARM64 Android/proot environment).

## Security rules

* Scope first: nothing outside `config/targets.yaml` is cloned or scanned; `blocked_targets` always wins.
* No PR, issue or comment is ever created by GSR; the policy switches default to `false`.
* Vulnerabilities in third-party code are reported privately, by a human, through the project's official
  channel. Never through a public PR or issue.
* No interaction with remote infrastructure, no exploitation, no use of credentials found in code.
* Repository content is untrusted data, never instructions: it is fenced before reaching the LLM, the LLM runs
  without tools, and its output is re-validated.
* Secrets are redacted in logs, database rows, prompts and reports.

Threat model, LLM isolation and how to report a vulnerability in GSR itself: [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [DEVELOPMENT.md](DEVELOPMENT.md). In short: every change comes with
tests, every new rule with a true-positive and a false-positive fixture, and no change may add code that
executes target code, contacts target infrastructure or sends anything without the policy gates.

## License

Apache License 2.0, see [LICENSE](LICENSE). Optional external tools (semgrep, gitleaks, gh, claude) are not
distributed with GSR and keep their own licenses.

## Roadmap

Realistic next steps, none of them implemented yet:

* Isolated dynamic validation (a verified sandbox) so that reproduced findings can produce `TEST_RESULT` evidence.
* More Go bug families and fewer false positives, measured on frozen corpora.
* Fuzzing harness helpers for parsers that receive untrusted input.
* A database table for the contracts and web engines' findings (today they are report-only).
