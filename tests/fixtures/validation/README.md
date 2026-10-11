# Validation corpora (independent of the development fixtures)

| Corpus | Development fixtures (rules tuned on them) | Validation corpus (measure only) |
|---|---|---|
| contracts.solidity | tests/fixtures/contracts/ (19 contracts, agent B) | validation/contracts/ (10 files, 59 labelled sites) |
| web.passive | tests/fixtures/web/{pos,neg}/ (72 fixtures, agent C) | validation/web/corpus/ (50 cases, 59 labels) |

Protocol (2026-10-09): cases written and labelled from public definitions (SWC registry, CWE/OWASP, vendor advisories,
historic incidents) BEFORE the first engine run on them; `labels.json` + every input frozen in `FROZEN.sha256`;
`scripts/validate_engines.py` refuses to measure a modified corpus. No rule may be changed to pass these cases:
an engine fix found here needs a NEW fixture in the development corpus and a NEW validation corpus version.

Truth values: VULN (should be flagged), SAFE (no finding of that category), AMBIGUOUS (verdict depends on context
not in the file), FACT (configuration fact: expected as OBSERVATION, never as a vulnerability), in_scope=false
(real issue the engine documents as out of scope). Each label carries its `source` (why the verdict holds).

Independence limit: the labeller (the orchestrating agent) knew the rule NAMES and the agents' summaries, but did
not read the rule code before freezing. A corpus written by someone who never saw the engines (human or blind
agent), or real audited code, is the next step. Metrics on ~60 labels are PRELIMINARY.
