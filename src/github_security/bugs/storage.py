"""SQLite persistence for ordinary bug candidates (tables bug_scans / bug_candidates / bug_occurrences / bug_events).

Same identity model as security findings (repository -> commit -> scan -> occurrence -> stable fingerprint), but
separate tables: a BugCandidate is never written to `findings`, and a Finding is refused here.

Dedup classes reported per scan:
  new       first time this fingerprint is seen in the repository
  known     already stored, nothing proposed yet
  proposed  a PR exists and is still open (PR_CREATED / PR_UPDATED / CHANGES_REQUESTED)
  refused   rejected by validation / patch review, or PR closed without merge
  merged    PR merged, yet the pattern is seen again (fix incomplete or reverted)
  gone      open candidate NOT seen by this full scan. NEVER "fixed": the cause is recorded in `gone_reason`
            (+ a GONE event with the facts used), see GONE_REASONS. A fix upstream is never inferred.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from ..storage.database import Database, now
from .model import BUG_STATUSES, BugCandidate

DETECTOR = "bugs.go/6"   # bump on ANY detector logic change: same commit + other version => detector-caused change
                         # /1 = 2026-10-08..09 (3 split-index variants shipped under it), /2 = guard tracing 2026-10-09
                         # /3 = split-index FN fixes (loops, closures, fallthrough, stale input) + submatch-index
                         # /4 = bug-family signals (late length guard, ignored acquire + deferred release) + nil-before-err-check
                         # /5 = family signal: split index fed to strconv.Parse* with discarded error
                         # /6 = guards: if/else exiting on every branch, len aliases (n := len(v)); never-returns
                         #      helpers limited to exit calls (a helper ending in `return` hid candidates)

# Why an open candidate is no longer produced. Deterministic, from facts only (commit, detector version, scope,
# proof traces); the detector is a pure function of (code, version, scope).
GONE_REASONS = {
    "detector_change:guard_recognized": "same commit, other detector version, and the new detector records a proof "
                                        "that a pre-existing guard protects the site",
    "detector_change": "same commit, other detector version: the code did not change, the detector did",
    "out_of_scope": "the file still exists but is no longer analysed (excluded dir, test, symlink, size)",
    "technical": "the file did not parse cleanly or no detection report was available: absence proves nothing",
    "code_changed": "other commit, same detector version: the code changed (NOT a verified fix)",
    "unknown": "cause not determined (e.g. commit and detector both changed)",
    "legacy_unclassified": "marked gone before causes were recorded (schema < 7)",
}

STATES = {
    "validation_state": ("NOT_STARTED", "VALIDATED", "REJECTED"),
    "reproduction_state": ("NOT_STARTED", "TASK_PLANNED", "REPRODUCED", "NOT_REPRODUCED"),
    "regression_test_state": ("NONE", "WRITTEN", "FAILS_BEFORE_PATCH", "PASSES_AFTER_PATCH"),
    "patch_state": ("NONE", "DRAFTED", "VERIFIED", "REJECTED"),
    "pr_state": ("NONE", "PR_CREATED", "PR_UPDATED", "CHANGES_REQUESTED", "PR_CLOSED", "PR_MERGED"),
}
PR_EVENTS = STATES["pr_state"][1:]
_OPEN_PR = ("PR_CREATED", "PR_UPDATED", "CHANGES_REQUESTED")


class DecisionError(ValueError):
    """A human decision or PR record refused (unknown id, other repository, empty reason, already processed)."""


def storage_fingerprint(repository: str, c: BugCandidate, ordinal: int = 0) -> str:
    base = hashlib.sha256(f"{repository.lower()}|{c.fingerprint}".encode()).hexdigest()
    return base if ordinal == 0 else hashlib.sha256(f"{base}#{ordinal}".encode()).hexdigest()


def dedup_class(row) -> str:
    if row["pr_state"] in _OPEN_PR:
        return "proposed"
    if row["pr_state"] == "PR_MERGED":
        return "merged"
    if row["pr_state"] == "PR_CLOSED" or "REJECTED" in (row["validation_state"], row["patch_state"]):
        return "refused"
    return "known"


class BugStore:
    def __init__(self, db: Database):
        self.db = db
        self.conn = db.conn

    # ---- scans
    def start_scan(self, slug: str, sha: str, workdir: str | None = None, detector: str = DETECTOR) -> str:
        rid = self.db.repo_id(slug)
        cid = self.db.commit_id(rid, sha)
        sid = uuid.uuid4().hex
        self.conn.execute("INSERT INTO bug_scans(id, repository_id, commit_id, workdir, detector, status, started_at)"
                          " VALUES (?,?,?,?,?, 'running', ?)", (sid, rid, cid, workdir, detector, now()))
        return sid

    def fail_scan(self, scan_id: str, error: str) -> None:
        self.conn.execute("UPDATE bug_scans SET status='failed', finished_at=?, stats=? WHERE id=?",
                          (now(), json.dumps({"error": error}), scan_id))

    def record(self, scan_id: str, candidates: list[BugCandidate], duration_ms: int = 0, report=None) -> dict:
        """`report` (go_detectors.DetectionReport) gives the scope and proof traces used to explain disappearances;
        without it a disappearance can only be classified from commit / detector version."""
        bad = [type(c).__name__ for c in candidates if not isinstance(c, BugCandidate)]
        if bad:
            raise TypeError(f"BugStore accepts BugCandidate objects only, got {sorted(set(bad))}")
        scan = self.conn.execute("SELECT b.*, r.slug FROM bug_scans b JOIN repositories r ON r.id=b.repository_id "
                                 "WHERE b.id=?", (scan_id,)).fetchone()
        rid, cid, slug = scan["repository_id"], scan["commit_id"], scan["slug"]
        groups: dict[str, list[BugCandidate]] = {}
        for c in candidates:
            groups.setdefault(c.fingerprint, []).append(c)
        keyed: list[tuple[str, BugCandidate]] = []
        for items in groups.values():                # identical code on several lines -> ordinal suffix
            lines = sorted({c.line for c in items})
            keyed += [(storage_fingerprint(slug, c, lines.index(c.line)), c) for c in items]
        classes: dict[str, int] = {}
        seen: set[str] = set()
        with self.db.tx() as tx:
            for fp, c in keyed:
                if fp in seen:
                    continue
                seen.add(fp)
                row = tx.execute("SELECT * FROM bug_candidates WHERE fingerprint=?", (fp,)).fetchone()
                if row is None:
                    cls = "new"
                    tx.execute(
                        """INSERT INTO bug_candidates(fingerprint, id, repository_id, detector, rule, category, function,
                             file, line, related_lines, explanation, suspicion, snippet, negative_evidence, ambiguity,
                             context, confidence, status, status_reason, first_seen_scan, last_seen_scan, first_commit_id,
                             last_commit_id, created_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (fp, self._short_id(tx, fp), rid, scan["detector"], c.rule, c.category, c.function, c.file,
                         c.line, json.dumps(c.related_lines), c.explanation, c.suspicion, c.snippet,
                         json.dumps(c.negative_evidence), json.dumps(c.ambiguity), json.dumps(c.context), c.confidence,
                         c.status, c.status_reason, scan_id, scan_id, cid, cid, now(), now()))
                else:
                    cls = dedup_class(row)
                    if row["state"] == "gone":
                        self._event(fp, "REAPPEARED", "state", "gone", "open", row["gone_reason"],
                                    {"scan": scan_id, "commit_id": cid}, tx)
                    status, reason = c.status, c.status_reason
                    if c.status == "BUG_CANDIDATE" and str(row["status_reason"]).startswith(("B3", "B4")):
                        status, reason = row["status"], row["status_reason"]   # keep the review outcome
                    tx.execute(
                        """UPDATE bug_candidates SET file=?, line=?, related_lines=?, suspicion=?, snippet=?,
                             negative_evidence=?, ambiguity=?, context=?, confidence=?, status=?, status_reason=?, state='open', gone_reason=NULL,
                             last_seen_scan=?, last_commit_id=?, updated_at=? WHERE fingerprint=?""",
                        (c.file, c.line, json.dumps(c.related_lines), c.suspicion, c.snippet,
                         json.dumps(c.negative_evidence), json.dumps(c.ambiguity), json.dumps(c.context), c.confidence,
                         status, reason, scan_id, cid, now(), fp))
                classes[cls] = classes.get(cls, 0) + 1
                tx.execute("INSERT OR REPLACE INTO bug_occurrences VALUES (?,?,?,?,?)", (fp, scan_id, cid, c.file, c.line))
            gone: dict[str, int] = {}
            for r in tx.execute("SELECT * FROM bug_candidates WHERE repository_id=? AND state='open'",
                                (rid,)).fetchall():
                if r["fingerprint"] not in seen:
                    why, facts = self._gone_reason(tx, r, scan, slug, report)
                    tx.execute("UPDATE bug_candidates SET state='gone', gone_reason=?, updated_at=? WHERE fingerprint=?",
                               (why, now(), r["fingerprint"]))
                    self._event(r["fingerprint"], "GONE", "state", "open", "gone", why, facts, tx)
                    gone[why] = gone.get(why, 0) + 1
            if gone:
                classes["gone"] = sum(gone.values())
            stats = {"candidates": len(seen), "dedup": classes, "gone_reasons": dict(sorted(gone.items())),
                     "scope": None if report is None else {"files": len(report.files), "skipped": report.skipped,
                                                           "parse_errors": report.parse_errors,
                                                           "suppressed": len(report.suppressed)},
                     "by_category": _count(c.category for _, c in keyed),
                     "by_status": _count(c.status for _, c in keyed)}
            tx.execute("UPDATE bug_scans SET status='done', finished_at=?, duration_ms=?, stats=? WHERE id=?",
                       (now(), duration_ms, json.dumps(stats), scan_id))
        return {"scan_id": scan_id, **stats}

    def _gone_reason(self, tx, row, scan, slug: str, report) -> tuple[str, dict]:
        """Cause of a disappearance, from facts only. Never concludes that the bug was fixed."""
        prev = tx.execute("SELECT s.detector, c.sha FROM bug_scans s JOIN commits c ON c.id=s.commit_id WHERE s.id=?",
                          (row["last_seen_scan"],)).fetchone()
        sha = tx.execute("SELECT sha FROM commits WHERE id=?", (scan["commit_id"],)).fetchone()[0]
        same_commit, same_detector = row["last_commit_id"] == scan["commit_id"], prev["detector"] == scan["detector"]
        facts = {"scan": scan["id"], "commit": sha, "detector": scan["detector"], "last_seen_scan": row["last_seen_scan"],
                 "last_seen_commit": prev["sha"], "last_seen_detector": prev["detector"], "file": row["file"],
                 "line": row["line"]}
        if report is None:
            return "technical", {**facts, "why": "no detection report (scope and proofs unknown)"}
        if row["file"] not in report.files:
            if row["file"] in report.parse_errors:
                return "technical", {**facts, "why": "file not indexed (parse error)"}
            exists = bool(scan["workdir"]) and (Path(scan["workdir"]) / row["file"]).is_file()
            if exists:
                return "out_of_scope", {**facts, "skipped": row["file"] in report.skipped}
            return ("code_changed" if not same_commit else "unknown"), {**facts, "file_present": False}
        proof = next((p for c, p in report.suppressed if storage_fingerprint(slug, c) == row["fingerprint"] or
                      (same_commit and (c.file, c.line, c.category, c.rule) ==
                       (row["file"], row["line"], row["category"], row["rule"]))), None)
        if proof is not None:
            facts["proof"] = proof
        elif row["file"] in report.parse_errors:     # partially parsed: the site may have been skipped
            return "technical", {**facts, "why": "file parsed with errors"}
        if same_commit and not same_detector:
            return ("detector_change:guard_recognized" if proof else "detector_change"), facts
        if not same_commit and same_detector:
            return "code_changed", facts      # with a proof: a guard is now present (possible fix, to verify)
        return "unknown", facts

    @staticmethod
    def _short_id(c, fp: str) -> str:
        for n in range(10, 65, 4):
            sid = "b" + fp[:n]
            if not c.execute("SELECT 1 FROM bug_candidates WHERE id=?", (sid,)).fetchone():
                return sid
        return "b" + fp

    # ---- queries
    def get(self, ident: str):
        return self.conn.execute(
            """SELECT b.*, r.slug AS repository, c.sha AS last_commit FROM bug_candidates b
               JOIN repositories r ON r.id=b.repository_id JOIN commits c ON c.id=b.last_commit_id
               WHERE b.id=? OR b.fingerprint=?""", (ident, ident)).fetchone()

    def list(self, slug: str | None = None, state: str | None = "open") -> list:
        q = """SELECT b.*, r.slug AS repository, c.sha AS last_commit FROM bug_candidates b
               JOIN repositories r ON r.id=b.repository_id JOIN commits c ON c.id=b.last_commit_id WHERE 1=1"""
        args: list = []
        if slug:
            q += " AND r.slug=?"; args.append(slug.lower())
        if state:
            q += " AND b.state=?"; args.append(state)
        return self.conn.execute(q + " ORDER BY b.file, b.line", args).fetchall()

    def actionable(self, slug: str | None = None) -> list:
        """Open candidates that may still be worked on: never re-propose what is proposed, refused or merged."""
        return [r for r in self.list(slug) if r["status"] in ("BUG_CANDIDATE", "LIKELY_BUG")
                and dedup_class(r) == "known"]

    def workdir_for(self, fp: str) -> str | None:
        row = self.conn.execute("SELECT s.workdir FROM bug_candidates b JOIN bug_scans s ON s.id=b.last_seen_scan "
                                "WHERE b.fingerprint=?", (fp,)).fetchone()
        return row[0] if row else None

    def events(self, fp: str) -> list:
        return self.conn.execute("SELECT * FROM bug_events WHERE bug_fp=? ORDER BY id", (fp,)).fetchall()

    # ---- lifecycle
    def _event(self, fp, kind, field=None, old=None, new=None, reason=None, data=None, conn=None) -> None:
        (conn or self.conn).execute("INSERT INTO bug_events(bug_fp, created_at, kind, field, old_value, new_value, reason, data)"
                          " VALUES (?,?,?,?,?,?,?,?)", (fp, now(), kind, field, old, new, reason,
                                                        json.dumps(data or {}, default=str)))

    def set_state(self, fp: str, field: str, value: str, reason: str | None = None, data: dict | None = None) -> None:
        if value not in STATES.get(field, ()):
            raise ValueError(f"invalid {field}={value!r}")
        row = self.conn.execute(f"SELECT {field} FROM bug_candidates WHERE fingerprint=?", (fp,)).fetchone()
        if row is None:
            raise KeyError(fp)
        self.conn.execute(f"UPDATE bug_candidates SET {field}=?, updated_at=? WHERE fingerprint=?", (value, now(), fp))
        self._event(fp, "STATE_CHANGE", field, row[0], value, reason, data)

    def resolve(self, repository: str, ident: str):
        """Candidate `ident` (short id or fingerprint) that must belong to `repository`, else DecisionError."""
        row = self.get(ident)
        if row is None:
            raise DecisionError(f"unknown bug candidate {ident!r}")
        if row["repository"] != repository.lower():
            raise DecisionError(f"{row['id']} belongs to {row['repository']}, not {repository}")
        return row

    def reject(self, repository: str, ident: str, reason: str) -> dict:
        """Reasoned HUMAN rejection: validation_state -> REJECTED (dedup "refused", never re-proposed), status and
        observations untouched. Distinct from a demonstrated FALSE_POSITIVE (status, rule B1), from an undetermined
        case (NEEDS_REVIEW, NOT_STARTED) and from a fixed bug (pr_state PR_MERGED). Trace = one STATE_CHANGE event."""
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise DecisionError("a specific justification is required (at least 10 characters)")
        row = self.resolve(repository, ident)
        if row["validation_state"] == "REJECTED":
            raise DecisionError(f"{row['id']} is already rejected; previous decision kept")
        busy = [f"{k}={row[k]}" for k, idle in (("validation_state", "NOT_STARTED"), ("patch_state", "NONE"),
                                                ("pr_state", "NONE")) if row[k] != idle]
        if row["status"] == "FALSE_POSITIVE":
            busy.append("status=FALSE_POSITIVE (already demonstrated by the detector)")
        if row["state"] != "open":
            busy.append(f"state={row['state']} ({row['gone_reason']})")
        if busy:
            raise DecisionError(f"{row['id']} already processed: {', '.join(busy)}")
        data = {"decision": "HUMAN_REJECTED", "origin": "human", "channel": "cli", "repository": row["repository"],
                "commit": row["last_commit"], "file": row["file"], "line": row["line"], "status": row["status"],
                "status_reason": row["status_reason"]}
        self.set_state(row["fingerprint"], "validation_state", "REJECTED", reason, data)
        return {"id": row["id"], "reason": reason, **data}

    def record_pr_event(self, fp: str, event: str, url: str | None = None, reason: str | None = None,
                        data: dict | None = None) -> bool:
        """GitHub outcome: kept with its reason for the merge-rate funnel. Idempotent: the same event for the same
        URL is not recorded twice (returns False)."""
        if event not in PR_EVENTS:
            raise ValueError(f"invalid PR event {event!r}")
        row = self.conn.execute("SELECT pr_state, pr_url FROM bug_candidates WHERE fingerprint=?", (fp,)).fetchone()
        if row is None:
            raise KeyError(fp)
        if row["pr_state"] == event and (url is None or row["pr_url"] == url):
            return False
        if url and row["pr_url"] and row["pr_url"] != url:
            raise DecisionError(f"candidate already linked to {row['pr_url']}, not {url}")
        self.set_state(fp, "pr_state", event, reason)
        self.conn.execute("UPDATE bug_candidates SET pr_url=COALESCE(?, pr_url), outcome_reason=COALESCE(?, "
                          "outcome_reason) WHERE fingerprint=?", (url, reason, fp))
        self._event(fp, "PR_EVENT", "pr_state", None, event, reason, {"url": url, **(data or {})})
        return True

    def add_review(self, fp: str, record: dict) -> None:
        if record["status"] not in BUG_STATUSES:
            raise ValueError(record["status"])
        old = self.conn.execute("SELECT status FROM bug_candidates WHERE fingerprint=?", (fp,)).fetchone()[0]
        self.conn.execute("UPDATE bug_candidates SET llm_review=?, status=?, status_reason=?, updated_at=? "
                          "WHERE fingerprint=?", (json.dumps(record["review"]), record["status"],
                                                  record["status_reason"], now(), fp))
        self._event(fp, "LLM_REVIEW", "status", old, record["status"], record["status_reason"],
                    {"model": record.get("model"), "duration_ms": record.get("duration_ms"),
                     "prompt_chars": record.get("prompt_chars"), "context_partial": record.get("context_partial"),
                     "review": record["review"]})

    def candidate_from_row(self, row) -> BugCandidate:
        """Rebuild the model object from a stored row (code is re-read from the checkout, never from the DB)."""
        c = BugCandidate(file=row["file"], line=row["line"], category=row["category"], rule=row["rule"],
                         function=row["function"], explanation=row["explanation"], suspicion=row["suspicion"],
                         snippet=row["snippet"], confidence=row["confidence"],
                         related_lines=json.loads(row["related_lines"]),
                         negative_evidence=json.loads(row["negative_evidence"]),
                         ambiguity=json.loads(row["ambiguity"]), context=json.loads(row["context"]),
                         status=row["status"], status_reason=row["status_reason"])
        return c

    # ---- metrics: the funnel is the main measure, not the number of candidates
    def metrics(self, slug: str | None = None) -> dict:
        rows = self.list(slug, state=None)
        n = len(rows)

        def cnt(pred):
            return sum(1 for r in rows if pred(r))
        events = self.conn.execute(
            "SELECT e.new_value, e.reason FROM bug_events e JOIN bug_candidates b ON b.fingerprint=e.bug_fp "
            "JOIN repositories r ON r.id=b.repository_id WHERE e.kind='PR_EVENT'" + (" AND r.slug=?" if slug else ""),
            ([slug.lower()] if slug else [])).fetchall()
        reviews = self.conn.execute(
            "SELECT COUNT(*) FROM bug_events e JOIN bug_candidates b ON b.fingerprint=e.bug_fp "
            "JOIN repositories r ON r.id=b.repository_id WHERE e.kind='LLM_REVIEW'" + (" AND r.slug=?" if slug else ""),
            ([slug.lower()] if slug else [])).fetchone()[0]
        return {
            "detected": n, "open": cnt(lambda r: r["state"] == "open"), "gone": cnt(lambda r: r["state"] == "gone"),
            "gone_reasons": _count(r["gone_reason"] for r in rows if r["state"] == "gone"),
            "by_category": _count(r["category"] for r in rows), "by_status": _count(r["status"] for r in rows),
            "llm_reviews": reviews,
            "funnel": {
                "candidates": cnt(lambda r: r["status"] in ("BUG_CANDIDATE", "LIKELY_BUG")),
                "validated": cnt(lambda r: r["validation_state"] == "VALIDATED"),
                "reproduced": cnt(lambda r: r["reproduction_state"] == "REPRODUCED"),
                "regression_test_fails_before_patch": cnt(lambda r: r["regression_test_state"] in
                                                          ("FAILS_BEFORE_PATCH", "PASSES_AFTER_PATCH")),
                "patch_verified": cnt(lambda r: r["patch_state"] == "VERIFIED"),
                "pr_created": cnt(lambda r: r["pr_state"] != "NONE"),
                "changes_requested": cnt(lambda r: r["pr_state"] == "CHANGES_REQUESTED"),
                "merged": cnt(lambda r: r["pr_state"] == "PR_MERGED"),
                "closed": cnt(lambda r: r["pr_state"] == "PR_CLOSED"),
            },
            "pr_outcome_reasons": _count(f"{e['new_value']}: {e['reason']}" for e in events if e["reason"]),
        }


def _count(items) -> dict:
    out: dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items()))
