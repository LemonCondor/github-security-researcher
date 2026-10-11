"""SQLite persistence.

Identity model:
  repository -> commit -> scan -> occurrence(file, line, evidence) -> finding(fingerprint)
A *finding* is a stable logical issue (fingerprint survives line moves and new commits).
An *occurrence* is where a given scan saw it. The four evidence layers are stored apart:
  detection (findings/occurrences) | llm_reviews | validations | verdicts
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ..analysis.findings import Finding

SCHEMA_VERSION = 7   # 1 = M3/M4, 2 = M5 (was mislabelled 1), 3 = decision engine, 4 = findings.extra + aliases,
                     # 5 = ordinary bug candidates (separate tables, see BUGS_DDL)
                     # 6 = organisation / repository discovery (separate tables, see DISCOVERY_DDL)
                     # 7 = bug_candidates.gone_reason (why a candidate disappeared; additive, no row removed)

SCHEMA = """
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
  extra TEXT NOT NULL DEFAULT '{}',           -- JSON: scanner-specific structured data (e.g. OSV advisory)
  state TEXT NOT NULL DEFAULT 'open',         -- open | gone (not seen by last full scan)
  status TEXT NOT NULL DEFAULT 'DETECTED',    -- DETECTED > ANALYZED > EVIDENCE_ASSESSED > verdict | READY_FOR_HUMAN_REVIEW
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

-- When a finding's fingerprint changes for a non-semantic reason (e.g. category re-mapping),
-- the new fingerprint is recorded as an alias of the original finding: history is preserved.
CREATE TABLE IF NOT EXISTS fingerprint_aliases (
  alias_fp TEXT PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  run_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  type TEXT NOT NULL,                         -- STATIC_DATAFLOW | SOURCE_TO_SINK | ... | LLM_REASONING
  source TEXT NOT NULL,
  description TEXT NOT NULL,
  strength TEXT NOT NULL,                     -- weak | moderate | strong
  supports INTEGER NOT NULL,
  contradicts INTEGER NOT NULL,
  reproducible INTEGER NOT NULL,
  status TEXT NOT NULL,                       -- VERIFIED | UNVERIFIED | ADVISORY
  independent INTEGER NOT NULL,
  data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY,
  finding_fp TEXT NOT NULL REFERENCES findings(fingerprint),
  run_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  final_verdict TEXT NOT NULL CHECK (final_verdict IN ('CONFIRMED', 'FALSE_POSITIVE', 'INCONCLUSIVE')),
  proposed_verdict TEXT,                      -- LLM proposal (advisory)
  rule TEXT NOT NULL,
  confidence_score REAL NOT NULL,             -- separate from final_verdict
  human_review_required INTEGER NOT NULL,
  decision_reason TEXT NOT NULL,              -- JSON: rules_applied, supporting/contradicting/missing evidence...
  score_trail TEXT NOT NULL                   -- JSON
);

CREATE INDEX IF NOT EXISTS ix_evidence_fp ON evidence(finding_fp, run_id);
CREATE INDEX IF NOT EXISTS ix_decisions_fp ON decisions(finding_fp);
CREATE INDEX IF NOT EXISTS ix_findings_repo ON findings(repository_id, state, status);
CREATE INDEX IF NOT EXISTS ix_occ_scan ON occurrences(scan_id);
"""


VALIDATIONS_DDL = """
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
"""

# Ordinary (non-security) bugs: own tables, own statuses, never joined into findings/decisions (R1-R5).
# Lifecycle columns prepare the chain candidate -> validated -> regression test -> patch -> PR -> merge.
BUGS_DDL = """
CREATE TABLE IF NOT EXISTS bug_scans (
  id TEXT PRIMARY KEY,
  repository_id INTEGER NOT NULL REFERENCES repositories(id),
  commit_id INTEGER NOT NULL REFERENCES commits(id),
  workdir TEXT,
  detector TEXT NOT NULL,                     -- detector set + version
  status TEXT NOT NULL,                       -- running | done | failed
  started_at TEXT NOT NULL,
  finished_at TEXT,
  duration_ms INTEGER,
  stats TEXT NOT NULL DEFAULT '{}'            -- JSON: counts by category/status/dedup class
);

CREATE TABLE IF NOT EXISTS bug_candidates (
  fingerprint TEXT PRIMARY KEY,               -- repo|file|category|rule|function|normalised code (+ordinal)
  id TEXT NOT NULL UNIQUE,
  repository_id INTEGER NOT NULL REFERENCES repositories(id),
  detector TEXT NOT NULL,
  rule TEXT NOT NULL,
  category TEXT NOT NULL,
  function TEXT NOT NULL,
  file TEXT NOT NULL,                         -- latest location
  line INTEGER NOT NULL,
  related_lines TEXT NOT NULL DEFAULT '[]',
  explanation TEXT NOT NULL,
  suspicion TEXT NOT NULL,
  snippet TEXT NOT NULL,                      -- small numbered excerpt only; full code = checkout at commit
  negative_evidence TEXT NOT NULL DEFAULT '[]',
  ambiguity TEXT NOT NULL DEFAULT '[]',
  context TEXT NOT NULL DEFAULT '[]',         -- JSON [{kind, file, start, end}] ranges for the reviewer (no code)
  confidence REAL NOT NULL,                   -- detector prior
  status TEXT NOT NULL CHECK (status IN ('BUG_CANDIDATE','LIKELY_BUG','NEEDS_REVIEW','FALSE_POSITIVE')),
  status_reason TEXT NOT NULL,
  llm_review TEXT,                            -- JSON, latest sanitized review (history in bug_events)
  validation_state TEXT NOT NULL DEFAULT 'NOT_STARTED',     -- NOT_STARTED | VALIDATED | REJECTED
  reproduction_state TEXT NOT NULL DEFAULT 'NOT_STARTED',   -- NOT_STARTED | TASK_PLANNED | REPRODUCED | NOT_REPRODUCED
  regression_test_state TEXT NOT NULL DEFAULT 'NONE',       -- NONE | WRITTEN | FAILS_BEFORE_PATCH | PASSES_AFTER_PATCH
  patch_state TEXT NOT NULL DEFAULT 'NONE',                 -- NONE | DRAFTED | VERIFIED | REJECTED
  pr_state TEXT NOT NULL DEFAULT 'NONE',      -- NONE | PR_CREATED | PR_UPDATED | CHANGES_REQUESTED | PR_CLOSED | PR_MERGED
  pr_url TEXT,
  outcome_reason TEXT,                        -- why rejected / closed / merged, when known
  state TEXT NOT NULL DEFAULT 'open',         -- open | gone (not seen by the last bug scan; NOT "fixed")
  gone_reason TEXT,                           -- bugs.storage.GONE_REASONS key while gone, else NULL
  first_seen_scan TEXT NOT NULL REFERENCES bug_scans(id),
  last_seen_scan TEXT NOT NULL REFERENCES bug_scans(id),
  first_commit_id INTEGER NOT NULL REFERENCES commits(id),
  last_commit_id INTEGER NOT NULL REFERENCES commits(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bug_occurrences (
  bug_fp TEXT NOT NULL REFERENCES bug_candidates(fingerprint),
  scan_id TEXT NOT NULL REFERENCES bug_scans(id),
  commit_id INTEGER NOT NULL REFERENCES commits(id),
  file TEXT NOT NULL,
  line INTEGER NOT NULL,
  PRIMARY KEY (bug_fp, scan_id)
);

-- Append-only history: reviews, lifecycle transitions and GitHub outcomes with their reasons.
CREATE TABLE IF NOT EXISTS bug_events (
  id INTEGER PRIMARY KEY,
  bug_fp TEXT NOT NULL REFERENCES bug_candidates(fingerprint),
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL,                         -- LLM_REVIEW | STATE_CHANGE | PR_EVENT | GONE | REAPPEARED
  field TEXT,
  old_value TEXT,
  new_value TEXT,
  reason TEXT,
  data TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_bugs_repo ON bug_candidates(repository_id, state, status);
CREATE INDEX IF NOT EXISTS ix_bug_events_fp ON bug_events(bug_fp);
"""

# Repository discovery (read-only GitHub metadata). Never joined into findings/bugs; a discovered repository is
# NOT a scan target: approval only records a human decision (config/targets.yaml stays the only scan scope).
DISCOVERY_DDL = """
CREATE TABLE IF NOT EXISTS disc_orgs (
  login TEXT PRIMARY KEY,                     -- GitHub login, lower-case
  display_login TEXT NOT NULL,
  name TEXT,
  category TEXT NOT NULL,                     -- science_agency | public_admin | company | foundation | community
  origin TEXT NOT NULL,                       -- configured | discovered
  review_state TEXT NOT NULL DEFAULT 'pending' CHECK (review_state IN ('pending','approved','rejected')),
  discovered_via TEXT,                        -- config file / search query
  website TEXT,                               -- GitHub "blog" field (as published by the org)
  domain_verified INTEGER,                    -- GitHub verified-domain badge (1/0, NULL = unknown)
  description TEXT,
  github_url TEXT,
  public_repos INTEGER,
  status TEXT NOT NULL DEFAULT 'unknown',     -- active | inactive | unknown | not_found
  verified_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disc_repos (
  repo_id INTEGER PRIMARY KEY,                -- GitHub numeric id: survives renames/transfers (dedup key)
  full_name TEXT NOT NULL UNIQUE,             -- OWNER/REPO, lower-case
  display_name TEXT NOT NULL,
  org_login TEXT NOT NULL REFERENCES disc_orgs(login),
  facts TEXT NOT NULL DEFAULT '{}',           -- JSON {field: {value, source}}: collected facts with provenance
  enriched_at TEXT,                           -- second-pass (tests/CI/PRs/policy) collection time
  score REAL,
  score_version TEXT,
  tier TEXT,                                  -- candidate | difficult | excluded
  recommendation TEXT,                        -- REVIEW | DEFER | EXCLUDE
  justification TEXT NOT NULL DEFAULT '{}',   -- JSON: components, reasons, constraints, missing
  human_decision TEXT NOT NULL DEFAULT 'none' CHECK (human_decision IN ('none','approved','rejected')),
  human_reason TEXT,
  decided_at TEXT,
  first_seen TEXT NOT NULL,
  last_checked TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disc_events (
  id INTEGER PRIMARY KEY,
  subject TEXT NOT NULL,                      -- org login or repo full_name
  created_at TEXT NOT NULL,
  kind TEXT NOT NULL,                         -- DISCOVERED | CHANGED | RENAMED | SCORED | DECISION | ORG_REVIEW
  field TEXT,
  old_value TEXT,
  new_value TEXT,
  data TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS disc_errors (
  id INTEGER PRIMARY KEY,
  run_id TEXT,
  created_at TEXT NOT NULL,
  scope TEXT NOT NULL,                        -- org | repo | run
  subject TEXT NOT NULL,
  endpoint TEXT,
  kind TEXT NOT NULL,                         -- not_found | rate_limited | api_error
  message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS disc_runs (
  id TEXT PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,                       -- running | done | stopped_rate_limit | failed
  orgs TEXT NOT NULL DEFAULT '[]',
  stats TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS ix_disc_repos_org ON disc_repos(org_login, recommendation);
CREATE INDEX IF NOT EXISTS ix_disc_events_subject ON disc_events(subject);
"""

_STATUS_MIGRATION = {
    "candidate": "DETECTED", "analyzing": "DETECTED", "reviewed": "ANALYZED",
    "VALIDATED_STATICALLY": "EVIDENCE_ASSESSED",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL") if str(path) != ":memory:" else None
        self.conn.executescript(SCHEMA)
        self.conn.executescript(VALIDATIONS_DDL)
        self.conn.executescript(BUGS_DDL)
        self.conn.executescript(DISCOVERY_DDL)
        self.migrations_applied = self._migrate()

    # --- schema migration (introspection-based: M5 DBs carry a wrong version label) ---
    def _columns(self, table: str) -> set[str]:
        return {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}

    def _migrate(self) -> list[str]:
        done: list[str] = []
        with self.tx() as c:
            if "workdir" not in self._columns("scans"):
                c.execute("ALTER TABLE scans ADD COLUMN workdir TEXT")
                done.append("scans.workdir")
            if "run_id" not in self._columns("validations"):
                c.execute("ALTER TABLE validations RENAME TO validations_v1")
                for stmt in VALIDATIONS_DDL.split(";"):
                    if stmt.strip():
                        c.execute(stmt)
                c.execute("""INSERT INTO validations(finding_fp, commit_id, created_at, run_id, validator, outcome,
                               signal, strength, details, data, evidence_dir, duration_ms)
                             SELECT finding_fp, commit_id, created_at, 'legacy-v1', validator, outcome, 'neutral',
                               'weak', details, '{}', evidence_dir, duration_ms FROM validations_v1""")
                done.append("validations rebuilt (v1 rows kept with run_id=legacy-v1)")
            if "extra" not in self._columns("findings"):
                c.execute("ALTER TABLE findings ADD COLUMN extra TEXT NOT NULL DEFAULT '{}'")
                done.append("findings.extra")
            if "basis" not in self._columns("verdicts"):
                c.execute("ALTER TABLE verdicts ADD COLUMN basis TEXT NOT NULL DEFAULT 'none'")
                done.append("verdicts.basis")
            if "gone_reason" not in self._columns("bug_candidates"):
                c.execute("ALTER TABLE bug_candidates ADD COLUMN gone_reason TEXT")
                done.append("bug_candidates.gone_reason")
            legacy = c.execute("SELECT fingerprint FROM bug_candidates WHERE state='gone' AND gone_reason IS NULL"
                               ).fetchall()
            for (fp,) in legacy:      # disappeared before causes were recorded: never re-labelled as fixed
                c.execute("UPDATE bug_candidates SET gone_reason='legacy_unclassified' WHERE fingerprint=?", (fp,))
                c.execute("INSERT INTO bug_events(bug_fp, created_at, kind, field, old_value, new_value, reason, data)"
                          " VALUES (?,?,'GONE','gone_reason',NULL,'legacy_unclassified',?,'{\"backfill\": true}')",
                          (fp, now(), "marked gone before schema 7: cause not recorded"))
            if legacy:
                done.append(f"gone_reason legacy_unclassified ({len(legacy)})")
            for old, new in _STATUS_MIGRATION.items():
                n = c.execute("UPDATE findings SET status=? WHERE status=?", (new, old)).rowcount
                if n:
                    done.append(f"status {old}->{new} ({n})")
            cur = c.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if cur is None or cur[0] != str(SCHEMA_VERSION):
                c.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
                done.append(f"schema_version {cur[0] if cur else None}->{SCHEMA_VERSION}")
        return done

    def close(self):
        self.conn.close()

    @contextmanager
    def tx(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    # --- repos / commits ---------------------------------------------------
    def repo_id(self, slug: str) -> int:
        slug = slug.lower()
        self.conn.execute("INSERT OR IGNORE INTO repositories(slug, created_at) VALUES (?, ?)", (slug, now()))
        return self.conn.execute("SELECT id FROM repositories WHERE slug=?", (slug,)).fetchone()[0]

    def commit_id(self, repo_id: int, sha: str) -> int:
        self.conn.execute("INSERT OR IGNORE INTO commits(repository_id, sha, first_scanned_at) VALUES (?,?,?)",
                          (repo_id, sha, now()))
        return self.conn.execute("SELECT id FROM commits WHERE repository_id=? AND sha=?",
                                 (repo_id, sha)).fetchone()[0]

    def last_scanned_commit(self, slug: str) -> str | None:
        row = self.conn.execute(
            """SELECT c.sha FROM scans s JOIN commits c ON c.id=s.commit_id
               JOIN repositories r ON r.id=s.repository_id
               WHERE r.slug=? AND s.status='done' ORDER BY s.finished_at DESC LIMIT 1""",
            (slug.lower(),)).fetchone()
        return row[0] if row else None

    # --- scans -------------------------------------------------------------
    def start_scan(self, slug: str, sha: str, mode: str = "full", workdir: str | None = None) -> str:
        rid = self.repo_id(slug)
        cid = self.commit_id(rid, sha)
        sid = uuid.uuid4().hex
        self.conn.execute("INSERT INTO scans(id, repository_id, commit_id, mode, workdir, status, started_at) "
                          "VALUES (?,?,?,?,?, 'running', ?)", (sid, rid, cid, mode, workdir, now()))
        return sid

    def fail_scan(self, scan_id: str, error: str):
        self.conn.execute("UPDATE scans SET status='failed', finished_at=?, scanners_skipped=? WHERE id=?",
                          (now(), json.dumps({"error": error}), scan_id))

    def record_scan(self, scan_id: str, findings: list[Finding], scanners_run: list[str],
                    scanners_skipped: dict, duration_ms: int, scanned_files: set[str] | None = None) -> dict:
        """Upsert findings for a finished scan. Idempotent per fingerprint.

        scanned_files=None means full scan: open findings not seen become 'gone'.
        For incremental scans, only findings in scanned_files can become 'gone'."""
        scan = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        rid, cid = scan["repository_id"], scan["commit_id"]
        bad = [type(f).__name__ for f in findings if not isinstance(f, Finding)]
        if bad:                                    # bug candidates have their own store (bugs.storage)
            raise TypeError(f"record_scan accepts security Finding objects only, got {sorted(set(bad))}")
        new = 0
        seen: set[str] = set()
        with self.tx() as c:
            for f in findings:
                f.fingerprint = self._resolve_fingerprint(c, rid, f)
                if f.fingerprint in seen:          # defensive: caller should have deduped
                    continue
                seen.add(f.fingerprint)
                row = c.execute("SELECT fingerprint FROM findings WHERE fingerprint=?", (f.fingerprint,)).fetchone()
                if row is None:
                    new += 1
                    c.execute(
                        """INSERT INTO findings(fingerprint, id, repository_id, scanner, rule, category, severity,
                             scanner_confidence, file, line, end_line, source, sink, description, evidence, refs,
                             extra, first_seen_scan, last_seen_scan, first_commit_id, last_commit_id, created_at,
                             updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (f.fingerprint, self._short_id(c, f.fingerprint), rid, f.scanner, f.rule, f.category,
                         f.severity, f.confidence, f.file, f.line, f.end_line, f.source, f.sink, f.description,
                         f.evidence, json.dumps(f.references), json.dumps(f.extra), scan_id, scan_id, cid, cid,
                         now(), now()))
                else:
                    c.execute(
                        """UPDATE findings SET file=?, line=?, end_line=?, severity=?, scanner_confidence=?,
                             category=?, description=?, refs=?, extra=?, state='open', last_seen_scan=?,
                             last_commit_id=?, updated_at=? WHERE fingerprint=?""",
                        (f.file, f.line, f.end_line, f.severity, f.confidence, f.category, f.description,
                         json.dumps(f.references), json.dumps(f.extra), scan_id, cid, now(), f.fingerprint))
                c.execute("INSERT OR REPLACE INTO occurrences VALUES (?,?,?,?,?,?)",
                          (f.fingerprint, scan_id, cid, f.file, f.line, f.end_line))
            # resolution tracking
            q = "SELECT fingerprint, file, scanner FROM findings WHERE repository_id=? AND state='open'"
            for r in c.execute(q, (rid,)).fetchall():
                if r["fingerprint"] in seen or r["scanner"] not in scanners_run:
                    continue            # a scanner that did not run cannot tell that its findings are gone
                if scanned_files is None or r["file"] in scanned_files:
                    c.execute("UPDATE findings SET state='gone', updated_at=? WHERE fingerprint=?",
                              (now(), r["fingerprint"]))
            c.execute("""UPDATE scans SET status='done', finished_at=?, duration_ms=?, scanners_run=?,
                           scanners_skipped=?, findings_count=?, new_findings_count=? WHERE id=?""",
                      (now(), duration_ms, json.dumps(scanners_run), json.dumps(scanners_skipped),
                       len(seen), new, scan_id))
        return {"findings": len(seen), "new": new}

    @staticmethod
    def _resolve_fingerprint(c, repo_id: int, f: Finding) -> str:
        """Map a freshly computed fingerprint to the stored finding it denotes.

        1. known alias -> original finding;
        2. otherwise, same repo/scanner/rule/file/evidence but a *different category* (category re-mapping,
           e.g. CWE-328 other -> weak-crypto) -> record an alias and keep the original identity.
        """
        if c.execute("SELECT 1 FROM findings WHERE fingerprint=?", (f.fingerprint,)).fetchone():
            return f.fingerprint
        row = c.execute("SELECT finding_fp FROM fingerprint_aliases WHERE alias_fp=?", (f.fingerprint,)).fetchone()
        if row:
            return row[0]
        row = c.execute(
            """SELECT fingerprint FROM findings WHERE repository_id=? AND scanner=? AND rule=? AND file=?
                 AND evidence=? AND category<>? ORDER BY created_at LIMIT 1""",
            (repo_id, f.scanner, f.rule, f.file, f.evidence, f.category)).fetchone()
        if row:
            c.execute("INSERT OR IGNORE INTO fingerprint_aliases VALUES (?,?,?,?)",
                      (f.fingerprint, row[0], f"category re-mapped to {f.category}", now()))
            return row[0]
        return f.fingerprint

    @staticmethod
    def _short_id(c, fp: str) -> str:
        for n in range(12, 65, 4):
            sid = fp[:n]
            if not c.execute("SELECT 1 FROM findings WHERE id=?", (sid,)).fetchone():
                return sid
        return fp

    # --- queries -----------------------------------------------------------
    def get_finding(self, ident: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT f.*, r.slug AS repository, c.sha AS last_commit FROM findings f
               JOIN repositories r ON r.id=f.repository_id JOIN commits c ON c.id=f.last_commit_id
               WHERE f.id=? OR f.fingerprint=?""", (ident, ident)).fetchone()

    def list_findings(self, slug: str | None = None, state: str | None = "open") -> list[sqlite3.Row]:
        q = """SELECT f.*, r.slug AS repository, c.sha AS last_commit FROM findings f
               JOIN repositories r ON r.id=f.repository_id JOIN commits c ON c.id=f.last_commit_id WHERE 1=1"""
        args: list = []
        if slug:
            q += " AND r.slug=?"; args.append(slug.lower())
        if state:
            q += " AND f.state=?"; args.append(state)
        q += """ ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                 WHEN 'low' THEN 3 ELSE 4 END, f.file, f.line"""
        return self.conn.execute(q, args).fetchall()

    def workdir_for(self, fp: str) -> str | None:
        row = self.conn.execute("SELECT s.workdir FROM findings f JOIN scans s ON s.id=f.last_seen_scan "
                                "WHERE f.fingerprint=?", (fp,)).fetchone()
        return row[0] if row else None

    def set_status(self, fp: str, status: str):
        self.conn.execute("UPDATE findings SET status=?, updated_at=? WHERE fingerprint=?", (status, now(), fp))

    # --- evidence layers ---------------------------------------------------
    def add_llm_review(self, fp: str, commit_id: int | None, *, model: str | None, context_sha256: str,
                       output: dict, duration_ms: int, error: str | None = None) -> int:
        cur = self.conn.execute(
            """INSERT INTO llm_reviews(finding_fp, commit_id, created_at, model, context_sha256, verdict,
                 confidence, severity, output_json, duration_ms, error) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (fp, commit_id, now(), model, context_sha256, output.get("verdict", "unknown"),
             float(output.get("confidence", 0.0)), output.get("severity"), json.dumps(output), duration_ms, error))
        return cur.lastrowid

    def latest_llm_review(self, fp: str):
        return self.conn.execute("SELECT * FROM llm_reviews WHERE finding_fp=? AND error IS NULL "
                                 "ORDER BY id DESC LIMIT 1", (fp,)).fetchone()

    def add_validation(self, fp: str, commit_id: int | None, *, run_id: str, validator: str, outcome: str,
                       signal: str, strength: str, details: str, data: dict | None = None,
                       evidence_dir: str | None = None, duration_ms: int = 0) -> int:
        if outcome not in ("CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE"):
            raise ValueError(outcome)
        if signal not in ("supports_real", "supports_false_positive", "neutral") or strength not in ("strong", "weak"):
            raise ValueError(f"{signal}/{strength}")
        cur = self.conn.execute(
            """INSERT INTO validations(finding_fp, commit_id, created_at, run_id, validator, outcome, signal,
                 strength, details, data, evidence_dir, duration_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fp, commit_id, now(), run_id, validator, outcome, signal, strength, details,
             json.dumps(data or {}), evidence_dir, duration_ms))
        return cur.lastrowid

    def add_regression_draft(self, fp: str, *, model: str | None, path: str, output: dict) -> int:
        return self.conn.execute(
            "INSERT INTO regression_drafts(finding_fp, created_at, model, path, output_json) VALUES (?,?,?,?,?)",
            (fp, now(), model, path, json.dumps(output))).lastrowid

    def regression_drafts_for(self, fp: str):
        return self.conn.execute("SELECT * FROM regression_drafts WHERE finding_fp=? ORDER BY id", (fp,)).fetchall()

    def validations_for(self, fp: str, latest_run_only: bool = False):
        if latest_run_only:
            return self.conn.execute(
                "SELECT * FROM validations WHERE finding_fp=? AND run_id=(SELECT run_id FROM validations "
                "WHERE finding_fp=? ORDER BY id DESC LIMIT 1) ORDER BY id", (fp, fp)).fetchall()
        return self.conn.execute("SELECT * FROM validations WHERE finding_fp=? ORDER BY id", (fp,)).fetchall()

    def add_verdict(self, fp: str, verdict: str, score: float, rationale: dict, decided_by: str = "pipeline",
                    basis: str = "none"):
        if verdict not in ("CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE"):
            raise ValueError(verdict)
        if basis not in ("static", "llm_only", "none"):
            raise ValueError(basis)
        if verdict == "CONFIRMED" and basis != "static":
            raise ValueError("CONFIRMED requires static evidence; the LLM can never confirm alone")
        self.conn.execute("INSERT INTO verdicts(finding_fp, created_at, verdict, confidence_score, basis, "
                          "rationale, decided_by) VALUES (?,?,?,?,?,?,?)",
                          (fp, now(), verdict, round(score, 3), basis, json.dumps(rationale), decided_by))
        self.set_status(fp, verdict)

    def latest_legacy_verdict(self, fp: str):
        return self.conn.execute("SELECT * FROM verdicts WHERE finding_fp=? ORDER BY id DESC LIMIT 1",
                                 (fp,)).fetchone()

    def latest_decision(self, fp: str):
        return self.conn.execute("SELECT * FROM decisions WHERE finding_fp=? ORDER BY id DESC LIMIT 1",
                                 (fp,)).fetchone()

    def latest_verdict(self, fp: str) -> dict | None:
        """Unified view: newest of decision-engine decision and legacy (M5) verdict."""
        d, v = self.latest_decision(fp), self.latest_legacy_verdict(fp)
        cand = []
        if d is not None:
            reason = json.loads(d["decision_reason"])
            cand.append((d["created_at"], 1, {
                "verdict": d["final_verdict"], "confidence_score": d["confidence_score"],
                "basis": reason.get("evidence_basis", "none"), "rationale": d["decision_reason"],
                "decided_by": "decision_engine", "created_at": d["created_at"], "source": "decision"}))
        if v is not None:
            cand.append((v["created_at"], 0, {
                "verdict": v["verdict"], "confidence_score": v["confidence_score"], "basis": v["basis"],
                "rationale": v["rationale"], "decided_by": v["decided_by"], "created_at": v["created_at"],
                "source": "legacy_verdict"}))
        return max(cand, key=lambda x: (x[0], x[1]))[2] if cand else None

    def add_evidence(self, fp: str, run_id: str, items: list) -> None:
        for e in items:
            self.conn.execute(
                """INSERT INTO evidence(finding_fp, run_id, created_at, type, source, description, strength,
                     supports, contradicts, reproducible, status, independent, data)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fp, run_id, now(), e.type, e.source, e.description, e.strength, int(e.supports),
                 int(e.contradicts), int(e.reproducible), e.status, int(e.independent), json.dumps(e.data)))

    def evidence_for(self, fp: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM evidence WHERE finding_fp=? AND run_id=(SELECT run_id FROM decisions WHERE finding_fp=? "
            "ORDER BY id DESC LIMIT 1) ORDER BY id", (fp, fp)).fetchall()

    def add_decision(self, fp: str, run_id: str, decision, score: float, trail: list[str],
                     extra_reason: dict | None = None) -> None:
        reason = {**decision.to_dict(), "confidence_score": score, **(extra_reason or {})}
        self.conn.execute(
            """INSERT INTO decisions(finding_fp, run_id, created_at, engine_version, final_verdict, proposed_verdict,
                 rule, confidence_score, human_review_required, decision_reason, score_trail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (fp, run_id, now(), decision.engine_version, decision.final_verdict, decision.proposed_verdict,
             decision.rule, score, int(decision.human_review_required), json.dumps(reason), json.dumps(trail)))
        self.set_status(fp, "READY_FOR_HUMAN_REVIEW" if decision.human_review_required else decision.final_verdict)

    def human_review_queue(self, slug: str | None = None) -> list[sqlite3.Row]:
        q = """SELECT f.id, f.fingerprint, r.slug AS repository, f.category, f.file, f.line, d.final_verdict,
                      d.confidence_score, d.rule, d.decision_reason
               FROM findings f JOIN repositories r ON r.id=f.repository_id
               JOIN decisions d ON d.id=(SELECT MAX(id) FROM decisions WHERE finding_fp=f.fingerprint)
               WHERE d.human_review_required=1"""
        args: list = []
        if slug:
            q += " AND r.slug=?"; args.append(slug.lower())
        return self.conn.execute(q + " ORDER BY d.final_verdict, d.confidence_score DESC", args).fetchall()

    # --- metrics -----------------------------------------------------------
    def metrics(self, slug: str | None = None) -> dict:
        where, args = ("WHERE r.slug=?", [slug.lower()]) if slug else ("", [])
        base = f"FROM findings f JOIN repositories r ON r.id=f.repository_id {where}"
        detected = self.conn.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
        fps_all = [r[0] for r in self.conn.execute(f"SELECT f.fingerprint {base}", args)]
        finals = {fp: self.latest_verdict(fp) for fp in fps_all}
        finals = {fp: v for fp, v in finals.items() if v is not None}
        verd: dict[str, int] = {}
        for v in finals.values():
            verd[v["verdict"]] = verd.get(v["verdict"], 0) + 1
        latest_dec = [self.latest_decision(fp) for fp in fps_all]
        latest_dec = [d for d in latest_dec if d is not None]
        conf_ind = conf_static_only = 0
        for d in latest_dec:
            if d["final_verdict"] != "CONFIRMED":
                continue
            sup = [e for e in json.loads(d["decision_reason"]).get("supporting_evidence", []) if e["independent"]]
            if sup:
                conf_ind += 1
                if all(e["type"] != "TEST_RESULT" for e in sup):
                    conf_static_only += 1
        drafts = self.conn.execute(
            f"""SELECT COUNT(d.id)
                {base.replace('FROM findings f', 'FROM findings f JOIN regression_drafts d ON d.finding_fp=f.fingerprint')}""",
            args).fetchone()[0]
        validated = self.conn.execute(
            f"""SELECT COUNT(DISTINCT va.finding_fp), AVG(va.duration_ms)
                {base.replace('FROM findings f', 'FROM findings f JOIN validations va ON va.finding_fp=f.fingerprint')}""",
            args).fetchone()
        by_status = dict(self.conn.execute(f"SELECT f.status, COUNT(*) {base} GROUP BY f.status", args).fetchall())
        scans = self.conn.execute(
            f"""SELECT COUNT(*), AVG(s.duration_ms), SUM(s.duration_ms) FROM scans s
                JOIN repositories r ON r.id=s.repository_id {where} {'AND' if where else 'WHERE'} s.status='done'""",
            args).fetchone()
        llm = self.conn.execute(
            f"""SELECT COUNT(*), AVG(l.duration_ms), SUM(l.error IS NOT NULL)
                {base.replace('FROM findings f', 'FROM findings f JOIN llm_reviews l ON l.finding_fp=f.fingerprint')}""",
            args).fetchone()
        decided = sum(verd.values())
        confirmed, fps, inc = verd.get("CONFIRMED", 0), verd.get("FALSE_POSITIVE", 0), verd.get("INCONCLUSIVE", 0)
        return {
            "findings_detected": detected,
            "findings_with_verdict": decided,
            "confirmed": confirmed,
            "false_positives": fps,
            "inconclusive": inc,
            "validation_rate": round((confirmed + fps) / decided, 3) if decided else None,
            "false_positive_rate": round(fps / decided, 3) if decided else None,
            "decision": {
                "note": "read the three rates together; a confirmation rate alone is not a quality measure",
                "total_findings": detected,
                "with_final_verdict": decided,
                "confirmed": confirmed, "false_positives": fps, "inconclusive": inc,
                "rates": {"confirmation": round(confirmed / decided, 3) if decided else None,
                          "false_positive": round(fps / decided, 3) if decided else None,
                          "inconclusive": round(inc / decided, 3) if decided else None},
                "avg_confidence_score": round(sum(v["confidence_score"] for v in finals.values()) / len(finals), 3)
                if finals else None,
                "human_review_required": sum(1 for d in latest_dec if d["human_review_required"]),
                "confirmed_with_independent_evidence": conf_ind,
                "confirmed_static_analysis_only": conf_static_only,
                "decided_by_engine": len(latest_dec),
                "llm_calls_avoided_by_static_triage": sum(
                    1 for d in latest_dec
                    if str(json.loads(d["decision_reason"]).get("contextual_analysis", "")).startswith("skipped")),
                "legacy_verdicts_only": sum(1 for v in finals.values() if v["source"] == "legacy_verdict"),
            },
            "by_status": by_status,
            "statically_validated": validated[0] or 0,
            "avg_validation_step_ms": int(validated[1] or 0),
            "regression_tests": {"llm_drafts": drafts, "executed": 0, "passed": 0, "failed": 0,
                                 "note": "drafts are UNEXECUTED by design and are never evidence"},
            "scans": {"count": scans[0], "avg_ms": int(scans[1] or 0), "total_ms": scans[2] or 0},
            "llm_reviews": {"count": llm[0], "avg_ms": int(llm[1] or 0), "errors": llm[2] or 0},
        }
