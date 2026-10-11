"""Human decisions on bug candidates (reasoned rejection) and recorded PR outcomes: traced, never a fix claim."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.storage import BugStore, DecisionError
from github_security.pipeline import detect_and_store_bugs
from github_security.scanner.base import ScanTarget
from github_security.storage.database import Database

FIX = Path(__file__).parent / "fixtures" / "bugs"
WHY = "guard at line 7 returns early when len(parts) < 2"


@pytest.fixture
def env(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIX / "ignored_error", repo)
    db = Database(tmp_path / "g.db")
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    store = BugStore(db)
    rows = {r["function"]: r for r in store.list("o/r")}
    return db, store, rows, repo


def test_reject_records_human_decision_and_keeps_observations(env):
    db, store, rows, _ = env
    b = rows["Persist"]
    d = store.reject("o/r", b["id"], f"  {WHY}  ")
    after = store.get(b["id"])
    assert (after["validation_state"], after["status"], after["state"]) == ("REJECTED", b["status"], "open")
    assert after["snippet"] == b["snippet"] and after["pr_state"] == "NONE"
    ev = store.events(b["fingerprint"])[-1]
    data = json.loads(ev["data"])
    assert (ev["kind"], ev["field"], ev["old_value"], ev["new_value"], ev["reason"]) == \
        ("STATE_CHANGE", "validation_state", "NOT_STARTED", "REJECTED", WHY)
    assert data["origin"] == "human" and data["decision"] == "HUMAN_REJECTED"
    assert (data["repository"], data["commit"], data["file"], data["line"]) == ("o/r", "c1", b["file"], b["line"])
    assert ev["created_at"] and d["id"] == b["id"]
    assert b["id"] not in {r["id"] for r in store.actionable("o/r")}           # never re-proposed


def test_reject_errors(env):
    _, store, rows, _ = env
    b = rows["Persist"]
    with pytest.raises(DecisionError, match="unknown"):
        store.reject("o/r", "bdeadbeef", WHY)
    with pytest.raises(DecisionError, match="belongs to o/r"):
        store.reject("other/repo", b["id"], WHY)
    for empty in ("", "   ", "no"):
        with pytest.raises(DecisionError, match="justification"):
            store.reject("o/r", b["id"], empty)
    store.reject("o/r", b["id"], WHY)
    with pytest.raises(DecisionError, match="already rejected"):
        store.reject("o/r", b["id"], WHY + " again")
    assert sum(e["new_value"] == "REJECTED" for e in store.events(b["fingerprint"])) == 1
    fp = next(r for r in rows.values() if r["status"] == "FALSE_POSITIVE")
    with pytest.raises(DecisionError, match="FALSE_POSITIVE"):
        store.reject("o/r", fp["id"], WHY)
    other = next(r for r in rows.values() if r["status"] != "FALSE_POSITIVE" and r["function"] != "Persist")
    store.record_pr_event(other["fingerprint"], "PR_CREATED", "https://github.com/o/r/pull/1")
    with pytest.raises(DecisionError, match="already processed: pr_state=PR_CREATED"):
        store.reject("o/r", other["id"], WHY)


def test_rejection_survives_rescan_gone_and_reappearance(tmp_path, env):
    db, store, rows, repo = env
    b = rows["PersistDeferred"]
    store.reject("o/r", b["id"], "defer of a best-effort cleanup, error is irrelevant here")
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c1"))
    assert store.get(b["id"])["validation_state"] == "REJECTED"
    moved = tmp_path / "ambiguous.go"
    (repo / "ambiguous.go").rename(moved)
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c2"))
    g = store.get(b["id"])
    assert (g["state"], g["gone_reason"], g["validation_state"]) == ("gone", "code_changed", "REJECTED")
    moved.rename(repo / "ambiguous.go")
    detect_and_store_bugs(db, ScanTarget("o/r", repo, "c3"))
    r = store.get(b["id"])
    assert (r["state"], r["validation_state"]) == ("open", "REJECTED")
    assert [e["kind"] for e in store.events(b["fingerprint"])] == ["STATE_CHANGE", "GONE", "REAPPEARED"]


def test_pr_record_idempotent_and_conflicting_url_refused(env):
    _, store, rows, _ = env
    fp = rows["Persist"]["fingerprint"]
    url = "https://github.com/o/r/pull/7"
    assert store.record_pr_event(fp, "PR_MERGED", url, "merged", {"merged_at": "2026-10-09T05:24:00Z"}) is True
    assert store.record_pr_event(fp, "PR_MERGED", url, "merged", {"merged_at": "2026-10-09T05:24:00Z"}) is False
    assert [e["kind"] for e in store.events(fp)] == ["STATE_CHANGE", "PR_EVENT"]
    with pytest.raises(DecisionError, match="already linked"):
        store.record_pr_event(fp, "PR_CLOSED", "https://github.com/o/r/pull/8")
    row = store.get(fp)
    assert (row["pr_state"], row["pr_url"], row["status"], row["state"]) == ("PR_MERGED", url, "BUG_CANDIDATE", "open")
    assert json.loads(store.events(fp)[-1]["data"])["merged_at"] == "2026-10-09T05:24:00Z"
    assert store.metrics("o/r")["funnel"]["merged"] == 1 and store.metrics("o/r")["funnel"]["validated"] == 0


# --------------------------------------------------------------------------- CLI

def _cli(tmp_path, *args):
    root = tmp_path / "gsr"
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "targets.yaml").write_text("targets: []\n")
    (root / "config" / "policies.yaml").write_text("")
    e = {**os.environ, "GSR_ROOT": str(root), "GSR_DATA_DIR": str(tmp_path / "data"), "GSR_WORKSPACE": str(tmp_path / "ws")}
    return subprocess.run(["github-sec", *args], capture_output=True, text=True, env=e, timeout=120)


def test_cli_reject_and_pr(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIX / "ignored_error", repo)
    data = json.loads(_cli(tmp_path, "bugs", "--path", str(repo), "--json").stdout)
    bid = next(c["id"] for c in data["candidates"] if c["function"] == "Persist")
    assert _cli(tmp_path, "bug-reject", "local:repo", bid, "--reason", " ").returncode == 2
    bad = _cli(tmp_path, "bug-reject", "o/other", bid, "--reason", WHY)
    assert bad.returncode == 2 and "belongs to local:repo" in bad.stderr
    assert _cli(tmp_path, "bug-reject", "local:repo", "bnope", "--reason", WHY).returncode == 2
    ok = _cli(tmp_path, "bug-reject", "local:repo", bid, "--reason", WHY)
    assert ok.returncode == 0 and "REJECTED" in ok.stdout and "unchanged" in ok.stdout
    again = _cli(tmp_path, "bug-reject", "local:repo", bid, "--reason", WHY)
    assert again.returncode == 2 and "already rejected" in again.stderr
    one = json.loads(_cli(tmp_path, "bug", bid, "--json").stdout)
    assert one["validation_state"] == "REJECTED" and one["status"] != "CONFIRMED"
    assert json.loads(one["events"][-1]["data"])["origin"] == "human"
    other = next(c["id"] for c in data["candidates"] if c["function"] == "Touch")
    wrong = _cli(tmp_path, "bug-pr", "local:repo", other, "--event", "PR_MERGED", "--url",
                 "https://github.com/x/y/pull/1")
    assert wrong.returncode == 2 and "not a pull request of local:repo" in wrong.stderr
