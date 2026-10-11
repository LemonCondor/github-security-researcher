
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS repositories (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS commits (
  id INTEGER PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id),
  sha TEXT NOT NULL,
  first_scanned_at TEXT NOT NULL,
  UNIQUE (repository_id, sha)
);

CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id),
  commit_id INTEGER NOT NULL REFERENCES commits(id),
  mode TEXT NOT NULL,                         -- full | incremental
  workdir TEXT,                               -- local checkout scanned
  status TEXT NOT NULL,                       -- running | done | failed
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER,
  scanners_run TEXT,                          -- JSON list
  scanners_skipped TEXT,                      -- JSON object
  findings_count INTEGER,
  new_findings_count INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,                    -- short public id
  repository_id INTEGER NOT NULL REFERENCES repositories(id),
  scanner TEXT NOT NULL,
  rule TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,                     -- scanner severity (detection layer)
  scanner_confidence REAL NOT NULL,           -- scanner prior (detection layer)
  file TEXT NOT NULL,                         -- latest location
  line INTEGER NOT NULL,
  end_line INTEGER,
  source TEXT,
  sink TEXT,
  description TEXT NOT NULL,
  evidence TEXT NOT NULL,
  refs TEXT NOT NULL,                         -- JSON list
  state TEXT NOT NULL DEFAULT 'open',         -- open | gone (not seen by last full scan)
  status TEXT NOT NULL DEFAULT 'DETECTED',    -- DETECTED > ANALYZED > VALIDATED_STATICALLY > verdict
  first_seen_scan TEXT NOT NULL REFERENCES scans(id),
  last_seen_scan TEXT NOT NULL REFERENCES scans(id),
  first_commit_id INTEGER NOT NULL REFERENCES commits(id),
  last_commit_id INTEGER NOT NULL REFERENCES commits(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS occurrences (
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  scan_id TEXT NOT NULL REFERENCES scans(id),
  commit_id INTEGER NOT NULL REFERENCES commits(id),
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  end_line INTEGER,
  PRIMARY KEY (finding_fp, scan_id)
);

CREATE TABLE IF NOT EXISTS llm_reviews (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  commit_id INTEGER REFERENCES commits(id),
  created_at TEXT NOT NULL,
  model TEXT,
  context_sha256 TEXT NOT NULL,
  verdict TEXT NOT NULL,                      -- confirmed|likely|false_positive|unknown
  confidence REAL NOT NULL,
  severity TEXT,
  output_json TEXT NOT NULL,                  -- full structured output
  duration_ms INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS validations (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  commit_id INTEGER REFERENCES commits(id),
  created_at TEXT NOT NULL,
  run_id TEXT NOT NULL,                       -- one validation run = several static steps
  validator TEXT NOT NULL,                    -- static.rule_reproduction, static.secret_analysis, ...
  outcome TEXT NOT NULL,                      -- step conclusion: CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE
  signal TEXT NOT NULL,                       -- supports_real | supports_false_positive | neutral
  strength TEXT NOT NULL,                     -- strong | weak
  details TEXT NOT NULL,                      -- human-readable reason
  data TEXT NOT NULL,                         -- JSON facts collected by the step (no secret values)
  evidence_dir TEXT,                          -- preserved evidence bundle
  duration_ms INTEGER
);

-- LLM-written regression tests: DRAFTS ONLY. Never executed by the tool, never used as evidence.
CREATE TABLE IF NOT EXISTS regression_drafts (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  created_at TEXT NOT NULL,
  model TEXT,
  path TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'UNEXECUTED' CHECK (status = 'UNEXECUTED'),
  output_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  created_at TEXT NOT NULL,
  verdict TEXT NOT NULL,                      -- CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE
  confidence_score REAL NOT NULL,             -- P(real vuln), separate from verdict
  basis TEXT NOT NULL,                        -- static | llm_only | none  (never 'execution')
  rationale TEXT NOT NULL,                    -- JSON: which layers drove the decision
  decided_by TEXT NOT NULL DEFAULT 'pipeline' -- pipeline | human
);

CREATE INDEX IF NOT EXISTS ix_findings_repo ON findings(repository_id, state, status);
CREATE INDEX IF NOT EXISTS ix_occ_scan ON occurrences(scan_id);

