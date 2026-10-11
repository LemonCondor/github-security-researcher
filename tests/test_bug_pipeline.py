"""Ordinary bugs wired into pipeline / SQLite / CLI, kept apart from security findings (R1-R5 untouched).
Fixtures are parsed only; no target code is executed, no network, no LLM (fake runner)."""
import json
import os
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security import config as cfg
from github_security.analysis.findings import Finding
from github_security.bugs import model as bm
from github_security.bugs.go_detectors import detect_go_bugs
from github_security.bugs.reproduction import plan_reproduction, pr_gate
from github_security.bugs.storage import BugStore
from github_security.pipeline import detect_and_store_bugs, review_bug, scan_repository
from github_security.scanner.base import Scanner, ScanTarget
from github_security.storage.database import SCHEMA_VERSION, Database

FIX = Path(__file__).parent / "fixtures" / "bugs"


class OneFinding(Scanner):
    name = "fake"

    def available(self):
        return True

    def scan(self, target):
        return [Finding(target.slug, target.commit, "positive.go", 23, "r1", "other", "low", 0.5, "fake", "d", "x")]


@pytest.fixture
def repo(tmp_path):
    dst = tmp_path / "repo"
    shutil.copytree(FIX / "ignored_error", dst)
    return dst


def db_(tmp_path):
    return Database(tmp_path / "g.db")


def test_pipeline_returns_both_kinds_separately(tmp_path, repo):
    db = db_(tmp_path)
    out = scan_repository(db, ScanTarget("o/r", repo, "c1"), [OneFinding()])
    assert out["security"]["findings"] == 1 and out["bugs"]["candidates"] == 6
    assert out["bugs"]["by_status"] == {"BUG_CANDIDATE": 2, "FALSE_POSITIVE": 1, "NEEDS_REVIEW": 3}
    assert db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
    assert db.conn.execute("SELECT COUNT(*) FROM bug_candidates").fetchone()[0] == 6
    assert {r[0] for r in db.conn.execute("SELECT scanner FROM findings")} == {"fake"}
    assert db.conn.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 0     # bugs never reach R1-R5
    assert not set(bm.BUG_STATUSES) & {r[0] for r in db.conn.execute("SELECT status FROM findings")}
    assert scan_repository(db, ScanTarget("o/r", repo, "c1"), [OneFinding()], bugs=False)["bugs"] is None


def test_no_cross_contamination_between_stores(tmp_path, repo):
    db = db_(tmp_path)
    cands = detect_go_bugs(repo)
    sid = db.start_scan("o/r", "c1")
    with pytest.raises(TypeError, match="security Finding objects only"):
        db.record_scan(sid, cands, [], {}, 0)
    store = BugStore(db)
    with pytest.raises(TypeError, match="BugCandidate objects only"):
        store.record(store.start_scan("o/r", "c1"), [OneFinding().scan(ScanTarget("o/r", repo, "c1"))[0]])
    store.record(store.start_scan("o/r", "c1"), cands)
    with pytest.raises(sqlite3.IntegrityError):                       # DB refuses security verdicts for bugs
        db.conn.execute("UPDATE bug_candidates SET status='CONFIRMED'")


def test_storage_keeps_required_fields_and_commit(tmp_path, repo):
    db = db_(tmp_path)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "abc123"))
    b = next(r for r in BugStore(db).list("o/r") if r["function"] == "Persist")
    assert (b["repository"], b["last_commit"], b["file"], b["line"], b["category"]) == \
        ("o/r", "abc123", "positive.go", 23, "ignored-error")
    assert b["detector"] == "bugs.go/6" and b["status"] == "BUG_CANDIDATE" and b["confidence"] == 0.5
    assert b["explanation"] and b["suspicion"] and "save(path)" in b["snippet"]
    assert json.loads(b["negative_evidence"]) == [] and json.loads(b["ambiguity"]) == []
    assert [x["kind"] for x in json.loads(b["context"])] == ["function", "callee"]
    for k, v in (("validation_state", "NOT_STARTED"), ("reproduction_state", "NOT_STARTED"),
                 ("regression_test_state", "NONE"), ("patch_state", "NONE"), ("pr_state", "NONE")):
        assert b[k] == v
    assert b["created_at"] and b["updated_at"] and b["llm_review"] is None
    t = next(r for r in BugStore(db).list("o/r") if r["function"] == "Touch")
    assert json.loads(t["negative_evidence"])[0].startswith("touch returns a literal nil")


def test_dedup_known_moved_identical_fixed(tmp_path, repo):
    db, store = db_(tmp_path), BugStore(db_(tmp_path))
    s1 = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    assert s1["dedup"] == {"new": 6}
    fps = {r["function"]: r["fingerprint"] for r in store.list("o/r")}
    p = repo / "positive.go"                                              # code moves down 3 lines
    p.write_text(p.read_text().replace('import "errors"\n', 'import "errors"\n\n// moved\n\n'))
    s2 = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))
    assert s2["dedup"] == {"known": 6}
    moved = store.get(fps["Persist"])
    assert moved["line"] == 26 and moved["last_commit"] == "c2"
    p.write_text(p.read_text().replace("\tsave(path)\n}", "\tsave(path)\n\tsave(path)\n}"))   # identical twice
    s3 = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c3"))
    assert s3["dedup"] == {"known": 6, "new": 1}
    (repo / "ambiguous.go").unlink()                                      # fixed upstream
    s4 = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c4"))
    assert s4["dedup"] == {"known": 4, "gone": 3} and s4["gone_reasons"] == {"code_changed": 3}
    assert store.get(fps["PersistDeferred"])["state"] == "gone"


def test_dedup_proposed_refused_merged_never_reproposed(tmp_path, repo):
    db = db_(tmp_path)
    store = BugStore(db)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    fp = {r["function"]: r["fingerprint"] for r in store.list("o/r")}
    assert {r["function"] for r in store.actionable("o/r")} == {"Persist", "Close"}
    store.record_pr_event(fp["Persist"], "PR_CREATED", url="https://example.invalid/pr/1")
    store.set_state(fp["Close"], "validation_state", "REJECTED", reason="intended: best effort")
    s = detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))
    assert s["dedup"] == {"known": 4, "proposed": 1, "refused": 1}
    assert store.actionable("o/r") == []
    store.record_pr_event(fp["Persist"], "PR_MERGED", reason="merged by maintainer")
    assert detect_and_store_bugs(db, ScanTarget("o/r", repo, "c3"))["dedup"]["merged"] == 1
    with pytest.raises(ValueError):
        store.set_state(fp["Persist"], "pr_state", "MERGED_BY_LLM")
    m = store.metrics("o/r")
    assert m["funnel"]["pr_created"] == 1 and m["funnel"]["merged"] == 1
    assert m["pr_outcome_reasons"] == {"PR_MERGED: merged by maintainer": 1}
    kinds = [e["kind"] for e in store.events(fp["Persist"])]
    assert kinds.count("PR_EVENT") == 2 and kinds.count("STATE_CHANGE") == 2


def test_review_persisted_and_bounded_by_rules(tmp_path, repo):
    db = db_(tmp_path)
    store = BugStore(db)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    b = next(r for r in store.list("o/r") if r["function"] == "Persist")
    answer = {"verdict": "LIKELY_BUG", "justification": "lost", "lines": [{"file": "positive.go", "line": 23}],
              "behavior_hypothesis": "h", "reproduction_condition": "Persist(\"\")", "injection_suspected": False}
    rec = review_bug(db, b["id"], runner=lambda *a, **k: dict(answer))
    assert rec["status"] == bm.LIKELY_BUG
    row = store.get(b["id"])
    assert row["status"] == bm.LIKELY_BUG and json.loads(row["llm_review"])["lines"]
    assert [e["kind"] for e in store.events(b["fingerprint"])] == ["LLM_REVIEW"]
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))              # rescan keeps the review outcome
    assert store.get(b["id"])["status"] == bm.LIKELY_BUG
    t = next(r for r in store.list("o/r") if r["function"] == "Touch")     # facts beat the review
    answer["lines"] = [{"file": "negative.go", "line": 24}]
    assert review_bug(db, t["id"], runner=lambda *a, **k: dict(answer))["status"] == bm.FALSE_POSITIVE
    assert store.metrics("o/r")["llm_reviews"] == 2


def test_reproduction_task_and_pr_gate(tmp_path, repo):
    got = {c.function: c for c in detect_go_bugs(repo)}
    t = plan_reproduction(got["Persist"])
    assert t.executable is False and t.category == "ignored-error" and t.lines == (23,)
    assert "fail" in t.trigger and t.expected_behavior and t.observed_behavior_expected and t.preconditions
    assert plan_reproduction(got["Touch"]) is None and plan_reproduction(got["PersistBestEffort"]) is None
    ow = {c.function: c for c in detect_go_bugs(FIX / "overwritten_error")}
    assert "first error" in plan_reproduction(ow["Run"]).expected_behavior
    db = db_(tmp_path)
    store = BugStore(db)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    fp = next(r for r in store.list("o/r") if r["function"] == "Persist")["fingerprint"]
    assert len(pr_gate(store.get(fp))) == 6           # fresh: status, validation, repro, test, patch, policy
    db.conn.execute("UPDATE bug_candidates SET status='LIKELY_BUG' WHERE fingerprint=?", (fp,))
    for f, v in (("validation_state", "VALIDATED"), ("reproduction_state", "REPRODUCED"),
                 ("regression_test_state", "PASSES_AFTER_PATCH"), ("patch_state", "VERIFIED")):
        store.set_state(fp, f, v)
    root = tmp_path / "cfgroot"                                        # own scope: never the user's targets.yaml
    (root / "config").mkdir(parents=True)
    shutil.copy(Path(__file__).parents[1] / "config" / "policies.yaml", root / "config" / "policies.yaml")
    (root / "config" / "targets.yaml").write_text(
        "targets:\n  - owner: o\n    repository: r\n    policy_reference: https://example.org/policy\n"
        "    disclosure: report_only\n    allow_pull_requests: false\nblocked_targets: []\n")
    settings = cfg.load(root)
    assert pr_gate(store.get(fp), settings, settings.targets[0]) == \
        ["policy: global allow_pr_creation is false"]                    # policy still blocks


def test_schema_v4_db_migrates_to_v5(tmp_path):
    p = tmp_path / "old.db"
    db = Database(p)
    for t in ("bug_events", "bug_occurrences", "bug_candidates", "bug_scans"):
        db.conn.execute(f"DROP TABLE {t}")
    db.conn.execute("UPDATE meta SET value='4' WHERE key='schema_version'")
    db.close()
    db2 = Database(p)
    assert SCHEMA_VERSION >= 5
    assert db2.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
    assert {"bug_scans", "bug_candidates", "bug_occurrences", "bug_events"} <= \
        {r[0] for r in db2.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


# --------------------------------------------------------------------------- CLI

def _env(tmp_path, targets="targets: []\n"):
    root = tmp_path / "gsr"
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "targets.yaml").write_text(targets)
    (root / "config" / "policies.yaml").write_text("")
    return {**os.environ, "GSR_ROOT": str(root), "GSR_DATA_DIR": str(tmp_path / "data"),
            "GSR_WORKSPACE": str(tmp_path / "ws")}


def _cli(env, *args):
    return subprocess.run(["github-sec", *args], capture_output=True, text=True, env=env, timeout=120)


def test_cli_bugs_local_path_text_and_json(tmp_path, repo):
    env = _env(tmp_path)
    out = _cli(env, "bugs", "--path", str(repo))
    assert out.returncode == 0, out.stderr
    assert "6 candidate(s)" in out.stdout and "positive.go:23" in out.stdout and "not confirmed" in out.stdout
    js = _cli(env, "bugs", "--path", str(repo), "--json")
    data = json.loads(js.stdout)
    assert data["repository"] == "local:repo" and data["dedup"] == {"known": 6}
    assert {c["status"] for c in data["candidates"]} == {"BUG_CANDIDATE", "FALSE_POSITIVE", "NEEDS_REVIEW"}
    bid = next(c["id"] for c in data["candidates"] if c["function"] == "Persist")
    one = json.loads(_cli(env, "bug", bid, "--json").stdout)
    assert one["reproduction_task"]["executable"] is False and one["pr_gate_unmet"]
    m = json.loads(_cli(env, "bug-metrics").stdout)
    assert m["detected"] == 6 and m["funnel"]["pr_created"] == 0


def test_cli_workspace_checkout_keeps_target_identity_and_sha(tmp_path, repo):
    ws = tmp_path / "ws" / "repos" / "owner" / "proj"
    shutil.copytree(repo, ws)
    g = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
         "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["init", "-q"], ["add", "."], ["commit", "-qm", "x"]):
        subprocess.run(["git", *cmd], cwd=ws, check=True, env=g, capture_output=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ws, capture_output=True, text=True).stdout.strip()
    env = _env(tmp_path, "targets:\n  - owner: owner\n    repository: proj\n    policy_reference: https://example.invalid/policy\n")
    data = json.loads(_cli(env, "bugs", "--path", str(ws), "--json").stdout)
    assert (data["repository"], data["commit"]) == ("owner/proj", sha)
    pinned = _env(tmp_path, "targets:\n  - owner: owner\n    repository: proj\n    policy_reference: https://example.invalid/policy\n"
                            "    commit: " + "a" * 40 + "\n")
    bad = _cli(pinned, "bugs", "--path", str(ws))
    assert bad.returncode == 3 and "expected pinned" in bad.stderr
    blocked = _env(tmp_path, "targets: []\n")
    assert _cli(blocked, "bugs", "--path", str(ws)).returncode == 3        # not a configured target: refused
