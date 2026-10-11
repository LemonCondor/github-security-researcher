# Security policy

## Reporting a vulnerability in GSR

Please report vulnerabilities in GSR itself privately, through GitHub's private vulnerability reporting
(the **Security** tab of this repository → *Report a vulnerability*). Do not open a public issue for a
security problem. Include the affected version or commit, the impact, and a minimal reproduction.
This is a volunteer project: there is no bug bounty and no guaranteed response time.

## Fundamental principle

**LLM analysis alone cannot produce CONFIRMED.**
The deterministic decision engine (`analysis/decision.py`) reads typed evidence (enums and booleans), never
free text. LLM reasoning is stored as `ADVISORY` evidence that can neither confirm nor dismiss a finding.
`CONFIRMED` requires independent, verified evidence that meets the category's proof criteria (ARCHITECTURE.md).

## Scope and disclosure (non-negotiable)

* Only repositories listed in `config/targets.yaml` are cloned or scanned; `blocked_targets` always wins.
* Third-party targets must cite the program policy (`policy_reference`) that authorizes research.
* No PR, issue or comment is created by GSR (`config/policies.yaml` switches are all `false`).
* A vulnerability in third-party code is **never** disclosed through a public PR or issue. Reports are drafts,
  submitted privately by a human through the program's official channel after review.
* Public PRs are only for non-sensitive fixes, opened by a human, where the project's policy allows it.
* No interaction with remote infrastructure, no exploitation, no use of credentials found in code
  (secrets are classified statically; their liveness is never tested).

## Trust boundaries: the agent as an attack surface

| Trusted | Untrusted (DATA, never instructions) |
|---|---|
| `config/*.yaml`, system prompts, policy code | repository files, comments, README, AGENTS.md, issues, generated files, scanner output derived from them |

Protections against instructions planted in analysed repositories:

* Repository snippets are wrapped in nonce-tagged `<untrusted_repository_content>` blocks; any attempt to
  close the fence from inside is neutralised. The system prompt forbids following embedded instructions and
  asks the model to flag injection attempts (`injection_suspected` ⇒ human review).
* The model runs as `claude -p --tools "" --strict-mcp-config --setting-sources "" --no-session-persistence
  --system-prompt …` in an empty temporary directory, with GitHub and API tokens removed from its environment.
  It has no tools: it cannot read files, run commands or reach the network.
* Model output is re-validated: enums, ranges, and every cited evidence line must exist in the context that was
  sent; positive verdicts without verifiable evidence are downgraded.
* The live prompt-injection test (`GSR_LIVE_LLM=1 pytest tests/test_milestone4.py`) checks this end to end.

## Execution

**No code from a target repository is executed.** Validation is static (re-parsing with semgrep/gitleaks,
reading files, tree-sitter). Any future dynamic validation would require a verified isolated environment
(no network, no host credentials) and an explicit policy change; it is not implemented.

## Clones

`git` runs with hooks disabled, `core.symlinks=false`, no submodules, no LFS smudge, no credential helper,
`protocol.file`/`ext` disabled and no global/system config; public repositories only; size cap.

## Secrets handling

* GitHub access lives in `gh`; GSR never reads the token. No API key is used for the LLM.
* Logs, database rows, evidence bundles and prompts go through redaction (`security/secrets.py`); gitleaks runs
  with `--redact=100`; secret lines are masked before any LLM call; validators store length/entropy only.
* The test fixtures contain **synthetic** secret-like strings (marked `Fixture`, `NotAReal…`, `synthetic`) to
  exercise the detectors. `.gitleaks.toml` allow-lists those fixture paths only.
* Never commit `.env`, `data/` or `workspace/`: they are git-ignored.
