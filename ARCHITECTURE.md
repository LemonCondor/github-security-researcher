# Architecture

```
src/github_security/
  cli.py                 argparse CLI (github-sec)
  config.py              trusted config: targets.yaml, policies.yaml, organizations.yaml (strict parsing)
  observability.py       JSON-lines events, always redacted
  pipeline.py            scan_and_store / review_finding / validate_finding / analyze / draft_regression_test
  github/client.py       GitHub API through the `gh` CLI (token never handled by this code)
  github/repositories.py hardened clone/update of in-scope public repos
  scanner/               Scanner interface; semgrep (internal taint rules + optional packs),
                         gitleaks (values redacted), OSV dependency scanner (lockfiles parsed, never installed),
                         go_dataflow (tree-sitter Go, HTTP request sources)
  analysis/findings.py   normalized Finding + stable fingerprint
  analysis/context.py    bounded progressive context (window, function, callers, callees, tests)
  analysis/evidence.py   typed evidence from static steps and (advisory) LLM output
  analysis/decision.py   deterministic decision engine R1-R5 + separate confidence score
  analysis/go_dataflow.py syntactic Go dataflow (go-dataflow/2)
  ai/                    prompts (trusted), reviewer (claude -p, no tools), regression drafts (UNEXECUTED)
  validation/            static validators (no execution), Go module relations (gomod.py)
  bugs/                  ordinary Go bug candidates: detectors (bugs.go), model/status rules, reproduction
                         plans, contextual review, lifecycle store, reconciliation, PR gate
  contracts/             Solidity engine (contracts.solidity, tree-sitter-solidity); optional slither adapter
  web/                   passive web engine (web.passive, stdlib only, no fetcher)
  engines/contract.py    EngineFinding / Evidence / DependencyMissing contract shared by contracts and web
  discovery/             read-only discovery and ranking of organisations' public repositories
  storage/database.py    SQLite schema + migrations
  security/              secret redaction, policy gates
rules/semgrep/           internal high-precision rules
tests/                   pytest; tests/fixtures/vulnapp = synthetic vulnerable app + ground truth;
                         tests/fixtures/validation = frozen, independently labelled corpora
scripts/                 evaluate.py, validate_engines.py, hunt.py (ranked Go triage), dupcheck.py (read-only)
```

## Data model (SQLite, `data/gsr.db`, schema v7)
`repositories → commits → scans → occurrences → findings(fingerprint)`, plus four separate layers per finding:
`findings` (detection) · `llm_reviews` (analysis) · `validations` (static steps, grouped by run_id) ·
`verdicts` (verdict, basis, confidence_score, rationale) · `regression_drafts` (status forced to UNEXECUTED).

### Fingerprint
`sha256(repo | file | category | rule | whitespace-normalized code line)` — no line number, no commit,
so a finding that moves or survives across commits keeps its identity. Identical code on different lines of
the same file gets an ordinal suffix; several rule matches on the same line merge. A finding not seen by a
later full scan is marked `gone` (and reopened if it comes back). Known limit: a file rename creates a new
fingerprint.

## Decision architecture
```
SCANNER -> CANDIDATE (findings, DETECTED)
        -> CONTEXTUAL_ANALYSIS (llm_reviews, ANALYZED; advisory)
        -> EVIDENCE_ASSESSMENT (analysis/evidence.py -> evidence table, EVIDENCE_ASSESSED)
        -> DECISION_ENGINE (analysis/decision.py -> decisions table)
        -> CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE   (+ READY_FOR_HUMAN_REVIEW status when required)
```
Per finding, stored separately: `detection` (findings) · `contextual_analysis` (llm_reviews) ·
`evidence` (typed items) · `confidence_score` + `proposed_verdict` + `final_verdict` + `decision_reason` (decisions).

### Evidence
`type` (STATIC_DATAFLOW, SOURCE_TO_SINK, DEPENDENCY_USAGE, CONFIGURATION, CODE_CONTEXT, TEST_RESULT,
NEGATIVE_EVIDENCE, LLM_REASONING) · `source` · `description` · `strength` (weak/moderate/strong) ·
`supports` · `contradicts` · `reproducible` · `status` (VERIFIED/UNVERIFIED/ADVISORY).
*Independent* = VERIFIED and not LLM_REASONING. LLM_REASONING is always ADVISORY/weak.

| Static step | Evidence produced |
|---|---|
| rule_reproduction reproduced / not | STATIC_DATAFLOW moderate (taint rule) or CODE_CONTEXT weak / NEGATIVE_EVIDENCE weak (contradicts) |
| non_production_path | CODE_CONTEXT strong, contradicts |
| secret_analysis | CONFIGURATION strong (provider format / private key) · moderate/weak · NEGATIVE_EVIDENCE strong (placeholder/env) |
| dependency_usage (scoped to manifest subtree) | DEPENDENCY_USAGE moderate supports (import != reachability) / weak contradicts |
| build_only_module (Go) — c1..c5 all verified | BUILD_ONLY_MODULE strong, contradicts |
| unverified scanner hit (if not reproduced) | STATIC_DATAFLOW weak UNVERIFIED |

### Go dependency relations (`validation/gomod.py`, parsing only)
`dependency_usage` classifies a vulnerable module relative to the go.mod that lists it (nested modules excluded):
`imported` (moderate support) · `tooling_pin` / `transitive_compiled` (weak support) · `transitive`, `unknown`
(neutral: *absence of a direct import is never safety evidence for an indirect dependency*) · `test_only`,
`direct_unused`, `graph_only` (weak contradiction, never sufficient alone).

`build_only_module` emits BUILD_ONLY_MODULE (strong) only if **all** hold: c1 separate module under a different
product module · c2 every .go file is a tools.go-style pin · c3 product neither imports nor requires/replaces it ·
c4 the vulnerable module is absent from the product's go.mod, go.sum and vendor/modules.txt · c5 no
Dockerfile/Containerfile references the module dir. Build-script usage is recorded as a supporting fact only.
Otherwise nothing is emitted and the finding stays INCONCLUSIVE.

### Pre-LLM triage (`github-sec analyze`)
Static steps + engine without LLM first. If the rule is R2 or R3 (`LLM_INVARIANT_DECISIVE_RULES`: they read
independent evidence only, so no LLM output can change them — tested exhaustively) the decision is recorded
with `contextual_analysis: skipped…` and the LLM is not called. Otherwise nothing is persisted by the triage and the
finding continues to CONTEXTUAL_ANALYSIS. Dependency findings carry their OSV advisory (`findings.extra`), which is
passed to the LLM as fenced untrusted data.

### Rules (deterministic, first match wins; engine reads only enums/booleans, never text)
1. **R1_CONTRADICTORY_EVIDENCE** — independent moderate+ evidence on both sides → INCONCLUSIVE
2. **R2_SAFE_CONTEXT** — independent *strong* contradicting evidence, no independent moderate+ support → FALSE_POSITIVE
3. **R3_PROOF_CRITERIA_MET** — independent evidence meets the category's proof criteria and *no* independent
   contradicting evidence of any strength → CONFIRMED.
   Criteria: secret → CONFIGURATION≥strong; code categories → SOURCE_TO_SINK≥strong or TEST_RESULT≥strong;
   vulnerable-dependency → DEPENDENCY_USAGE≥strong or TEST_RESULT≥strong. LLM_REASONING never qualifies.
4. **R4_LLM_CLAIM_WITHOUT_PROOF** — the LLM proposes CONFIRMED/FALSE_POSITIVE, nothing independent decides → INCONCLUSIVE
5. **R5_INSUFFICIENT_EVIDENCE** — default → INCONCLUSIVE

Today no validator emits SOURCE_TO_SINK/TEST_RESULT (no execution, static only), so code findings cannot be
CONFIRMED: this is intended.

### Confidence score
`decision.confidence_score()` = scanner prior + per-evidence deltas (LLM weighted by its confidence), clamped
[0.01, 0.99]. It is never read by `decide()` and never depends on the verdict: 0.99/INCONCLUSIVE and
0.30/CONFIRMED are both valid.

### Human review
INCONCLUSIVE and CONFIRMED always require human review (status READY_FOR_HUMAN_REVIEW; `github-sec review-queue`).
FALSE_POSITIVE is kept in history; it requires review only if the LLM disagreed or injection was suspected.
Nothing is ever disclosed or opened automatically.

### Schema migrations
Introspection-based (`Database._migrate`): v1 (M3/M4) and v2 (M5, mislabelled version 1) databases are upgraded
in place to v3; legacy validations are kept (`run_id=legacy-v1`), legacy verdicts remain readable and are
superseded by newer engine decisions.

Later versions: v4 `findings.extra` + fingerprint aliases, v5-v7 ordinary-bug tables (`bug_scans`,
`bug_candidates`, `bug_occurrences`, `bug_events`, with `gone_reason`) and discovery tables (`disc_*`).

## Ordinary bug pipeline (`github-sec bugs`)

Separate from the security pipeline: a bug candidate never becomes CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE.
```
bugs.go detectors (tree-sitter) -> BugCandidate (BUG_CANDIDATE | NEEDS_REVIEW | FALSE_POSITIVE + proof)
  -> optional contextual review (LIKELY_BUG only with verifiable cited lines)
  -> lifecycle states: validation, reproduction, regression test, patch, PR outcome (recorded by a human)
```
* Categories: ignored-error, overwritten-error, unchecked-split-index, unchecked-submatch-index,
  nil-before-err-check. A suppressed site keeps the proof of the guard that makes it safe.
* Bug-family signals (late length guard, ignored acquire + deferred release that can panic, split element fed
  to `strconv.Parse*` with a discarded error) only change the ranking, never the status rules.
* Reconciliation across scans: a candidate that disappears is `GONE` with a reason (detector change, code
  change, out of scope...), and `REAPPEARED` if it comes back. `DETECTOR` (bugs/storage.py) is versioned.
* The PR gate (`github-sec bug ID`) lists what is still missing; the global policy switch keeps it closed.

## Contracts and web engines

Both return `EngineFinding`s (`engines/contract.py`) with a typed location, rule, status (OBSERVATION,
CANDIDATE, NEEDS_REVIEW, FALSE_POSITIVE), validation method and limitations; CONFIRMED is refused by the contract.
They are report-only (no database table yet). `contracts.solidity` parses local `.sol` files; `web.passive` reads
local captures and has no network code (a test patches sockets to prove it). Their precision/recall on the
frozen corpora (`scripts/validate_engines.py`) is preliminary.

## Discovery (`github-sec discover`)

Collects public metadata of the organisations listed in `config/organizations.yaml` (after a human approves
each organisation), ranks repositories, and records human approvals/rejections. It never clones, scans or
adds scan targets: `config/targets.yaml` remains the only scope.
