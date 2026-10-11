"""Reconciliation of stored bug candidates with a new detection run: a disappearance is explained, never a "fix"."""
from __future__ import annotations

import json
import sqlite3

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.go_detectors import detect_go_report
from github_security.bugs.storage import DETECTOR, GONE_REASONS, BugStore
from github_security.pipeline import detect_and_store_bugs
from github_security.scanner.base import ScanTarget
from github_security.storage.database import SCHEMA_VERSION, Database

GO = '''package p

import "strings"

func Guarded(s string) string {
	parts := strings.Split(s, "=")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func Unguarded(s string) string {
	parts := strings.SplitN(s, "\\n", 2)
	return parts[1]
}
'''


@pytest.fixture
def repo(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / "p.go").write_text(GO)
    return d


def _old_scan(db, repo, commit="c1", extra=()):
    """What a guard-blind detector (older version) stored: the current candidates + the sites now proven safe."""
    rep = detect_go_report(repo)
    store = BugStore(db)
    sid = store.start_scan("o/r", commit, str(repo), detector="bugs.go/1")
    return store.record(sid, rep.candidates + [c for c, _ in rep.suppressed] + list(extra), 0, rep)


def _by_fn(store, fn):
    return next(r for r in store.list("o/r", state=None) if r["function"] == fn)


def test_report_traces_proven_guard_and_keeps_unguarded_candidate(repo):
    rep = detect_go_report(repo)
    assert [(c.function, c.line) for c in rep.candidates] == [("Unguarded", 15)]
    (site, proof), = rep.suppressed
    assert (site.function, site.line, site.category) == ("Guarded", 10, "unchecked-split-index")
    assert proof["kind"] == "guard_recognized" and proof["index"] == 1 and proof["proven_len"] >= 2
    assert rep.files == {"p.go"} and rep.parse_errors == []


def test_same_commit_new_detector_guard_recognized_is_not_fixed(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    store = BugStore(db)
    assert _old_scan(db, repo)["dedup"] == {"new": 2}
    fp = _by_fn(store, "Guarded")["fingerprint"]
    store.set_state(fp, "validation_state", "REJECTED", "human: guard at line 7")     # manual decision kept
    s2 = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    assert DETECTOR != "bugs.go/1"
    assert s2["dedup"] == {"known": 1, "gone": 1}
    assert "fixed" not in s2["dedup"] and s2["gone_reasons"] == {"detector_change:guard_recognized": 1}
    g = _by_fn(store, "Guarded")
    assert (g["state"], g["gone_reason"], g["validation_state"]) == ("gone", "detector_change:guard_recognized",
                                                                      "REJECTED")
    ev = [e for e in store.events(fp) if e["kind"] == "GONE"][-1]
    data = json.loads(ev["data"])
    assert data["commit"] == data["last_seen_commit"] == "c1"
    assert (data["last_seen_detector"], data["detector"]) == ("bugs.go/1", DETECTOR)
    assert data["proof"]["kind"] == "guard_recognized"
    # history kept: the old occurrence is still there, the row is not deleted
    assert db.conn.execute("SELECT COUNT(*) FROM bug_occurrences WHERE bug_fp=?", (fp,)).fetchone()[0] == 1
    assert store.metrics("o/r")["gone_reasons"] == {"detector_change:guard_recognized": 1}


def test_reappearance_reopens_and_clears_reason(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    store = BugStore(db)
    _old_scan(db, repo)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    _old_scan(db, repo)
    g = _by_fn(store, "Guarded")
    assert (g["state"], g["gone_reason"]) == ("open", None)
    assert [e["kind"] for e in store.events(g["fingerprint"])] == ["GONE", "REAPPEARED"]


def test_same_commit_new_detector_without_proof(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    store = BugStore(db)
    ghost = detect_go_report(repo).candidates[0]
    ghost = type(ghost)(**{**ghost.to_dict(), "function": "Ghost", "fingerprint": ""})
    _old_scan(db, repo, extra=[ghost])
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    assert s["gone_reasons"] == {"detector_change": 1, "detector_change:guard_recognized": 1}


def test_other_commit_same_detector_is_code_changed_not_fixed(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    store = BugStore(db)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    (repo / "p.go").write_text(GO.replace('parts := strings.SplitN(s, "\\n", 2)\n\treturn parts[1]',
                                        'parts := strings.SplitN(s, "\\n", 2)\n\tif len(parts) < 2 {\n'
                                        '\t\treturn ""\n\t}\n\treturn parts[1]'))
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))
    assert s["gone_reasons"] == {"code_changed": 1}
    u = _by_fn(store, "Unguarded")
    data = json.loads([e for e in store.events(u["fingerprint"]) if e["kind"] == "GONE"][-1]["data"])
    assert data["proof"]["kind"] == "guard_recognized"          # a guard is now present: possible fix, to verify
    assert u["status"] != "CONFIRMED" and u["pr_state"] == "NONE"


def test_both_changed_is_unknown(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    _old_scan(db, repo, "c1")
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))
    assert s["gone_reasons"] == {"unknown": 1}


def test_out_of_scope_and_technical(tmp_path, repo):
    db = Database(tmp_path / "g.db")
    store = BugStore(db)
    (repo / "p_test.go").write_text(GO.replace("Guarded", "TGuarded").replace("Unguarded", "TUnguarded"))
    rep = detect_go_report(repo, include_tests=True)
    store.record(store.start_scan("o/r", "c1", str(repo)), rep.candidates, 0, rep)
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))          # default scope excludes _test.go
    assert s["gone_reasons"] == {"out_of_scope": 1}
    s = store.record(store.start_scan("o/r", "c1", str(repo)), [], 0, None)   # no report: absence proves nothing
    assert s["gone_reasons"] == {"technical": 1}
    assert set(s["gone_reasons"]) <= set(GONE_REASONS)


def test_schema_v6_gone_rows_backfilled_without_loss(tmp_path, repo):
    p = tmp_path / "old.db"
    db = Database(p)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    db.conn.execute("UPDATE bug_candidates SET state='gone'")
    db.conn.execute("ALTER TABLE bug_candidates DROP COLUMN gone_reason")
    db.conn.execute("UPDATE meta SET value='6' WHERE key='schema_version'")
    n = db.conn.execute("SELECT COUNT(*) FROM bug_candidates").fetchone()[0]
    db.close()
    db2 = Database(p)
    assert SCHEMA_VERSION == 7 and "bug_candidates.gone_reason" in db2.migrations_applied
    rows = db2.conn.execute("SELECT state, gone_reason FROM bug_candidates").fetchall()
    assert len(rows) == n and {tuple(r) for r in rows} == {("gone", "legacy_unclassified")}
    assert db2.conn.execute("SELECT COUNT(*) FROM bug_events WHERE kind='GONE'").fetchone()[0] == n
    db2.close()
    assert Database(p).migrations_applied == []                           # idempotent
    with pytest.raises(sqlite3.IntegrityError):
        Database(p).conn.execute("UPDATE bug_candidates SET status='CONFIRMED'")


def test_partially_parsed_file_with_proof_is_guard_recognized(tmp_path, repo):
    (repo / "p.go").write_text(GO + "\nfunc Broken( {\n")                  # parse error elsewhere in the file
    db = Database(tmp_path / "g.db")
    rep = detect_go_report(repo)
    assert "p.go" in rep.parse_errors and "p.go" in rep.files
    _old_scan(db, repo)
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    assert s["gone_reasons"] == {"detector_change:guard_recognized": 1}
