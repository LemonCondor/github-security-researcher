import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from github_security.analysis.findings import Finding
from github_security.pipeline import finding_report, scan_and_store
from github_security.scanner.base import Scanner, ScanTarget
from github_security.scanner.runner import dedupe
from github_security.scanner.semgrep import SemgrepScanner
from github_security.storage.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"


class FakeScanner(Scanner):
    """Emits findings for every line containing 'SINK(' — deterministic, no tools."""
    name = "fake"

    def available(self):
        return True

    def scan(self, t: ScanTarget):
        out = []
        for p in sorted(t.path.rglob("*.py")):
            rel = str(p.relative_to(t.path))
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if "SINK(" in line:
                    for rule in ("r1", "r1"):          # same rule twice on one line => must merge
                        out.append(Finding(repository=t.slug, commit=t.commit, file=rel, line=i, rule=rule,
                                           category="command-injection", severity="high", confidence=0.6,
                                           scanner=self.name, description="d", evidence=line.strip()))
        return out


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "gsr.db")
    yield d
    d.close()


def write(repo: Path, text: str):
    repo.mkdir(exist_ok=True)
    (repo / "a.py").write_text(text)


def scan(db, repo, commit):
    return scan_and_store(db, ScanTarget("o/r", repo, commit), [FakeScanner()])


def test_second_identical_scan_creates_no_duplicates(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "x=1\nSINK(a)\nSINK(b)\n")
    s1 = scan(db, repo, "c1")
    s2 = scan(db, repo, "c1")
    assert (s1["findings"], s1["new"]) == (2, 2)
    assert (s2["findings"], s2["new"]) == (2, 0)
    assert db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
    assert db.conn.execute("SELECT COUNT(*) FROM scans WHERE status='done'").fetchone()[0] == 2
    assert db.conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0] == 1
    assert db.conn.execute("SELECT COUNT(*) FROM occurrences").fetchone()[0] == 4   # 2 per scan


def test_fingerprint_stable_when_code_moves_to_new_commit(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "SINK(a)\n")
    scan(db, repo, "c1")
    fp1 = db.list_findings()[0]["fingerprint"]
    write(repo, "# new header\n\n\nSINK(a)\n")
    s2 = scan(db, repo, "c2")
    rows = db.list_findings()
    assert s2["new"] == 0 and len(rows) == 1
    f = rows[0]
    assert f["fingerprint"] == fp1 and f["line"] == 4 and f["last_commit"] == "c2"
    occ = db.conn.execute("SELECT c.sha, o.line FROM occurrences o JOIN commits c ON c.id=o.commit_id "
                          "ORDER BY o.rowid").fetchall()
    assert [tuple(o) for o in occ] == [("c1", 1), ("c2", 4)]


def test_identical_code_on_two_lines_is_two_findings_same_line_merges(tmp_path):
    mk = lambda line, rule="r": Finding(repository="o/r", commit="c", file="a.py", line=line, rule=rule,
                                        category="xss", severity="low", confidence=0.5, scanner="s",
                                        description="d", evidence="SINK(a)")
    out = dedupe([mk(3), mk(3), mk(10)])
    assert len(out) == 2 and len({f.fingerprint for f in out}) == 2


def test_fixed_finding_becomes_gone_and_reappears(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "SINK(a)\nSINK(b)\n")
    scan(db, repo, "c1")
    write(repo, "SINK(a)\n")
    scan(db, repo, "c2")
    states = {r["evidence"]: r["state"] for r in db.list_findings(state=None)}
    assert states == {"SINK(a)": "open", "SINK(b)": "gone"}
    write(repo, "SINK(a)\nSINK(b)\n")
    s3 = scan(db, repo, "c3")
    assert s3["new"] == 0 and all(r["state"] == "open" for r in db.list_findings(state=None))


def test_repos_are_isolated(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "SINK(a)\n")
    scan_and_store(db, ScanTarget("o/one", repo, "c"), [FakeScanner()])
    scan_and_store(db, ScanTarget("o/two", repo, "c"), [FakeScanner()])
    assert len(db.list_findings("o/one")) == 1 and len(db.list_findings("o/two")) == 1
    assert db.conn.execute("SELECT COUNT(*) FROM commits").fetchone()[0] == 2


def test_failed_scan_is_recorded_and_not_used_as_baseline(db, tmp_path):
    class Boom(FakeScanner):
        def scan(self, t):
            raise RuntimeError("crash")
    repo = tmp_path / "r"
    write(repo, "SINK(a)\n")
    scan(db, repo, "c1")
    with pytest.raises(RuntimeError):
        scan_and_store(db, ScanTarget("o/r", repo, "c2"), [Boom()])
    assert db.conn.execute("SELECT status FROM scans ORDER BY started_at DESC LIMIT 1").fetchone()[0] == "failed"
    assert db.last_scanned_commit("o/r") == "c1"


def test_finding_report_links_all_layers_separately(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "SINK(a)\n")
    scan(db, repo, "c1")
    fp = db.list_findings()[0]["fingerprint"]
    rep = finding_report(db, fp[:12])
    d = rep["detection"]
    assert (rep["repository"], d["commit"], d["file"], d["line"], d["rule"]) == ("o/r", "c1", "a.py", 1, "r1")
    assert rep["llm_review"] is None and rep["static_validation"] == [] and rep["verdict"] is None
    assert rep["status"] == "DETECTED"
    db.add_llm_review(fp, None, model="m", context_sha256="h", output={"verdict": "likely", "confidence": 0.7},
                      duration_ms=5)
    db.add_validation(fp, None, run_id="r1", validator="static.x", outcome="INCONCLUSIVE", signal="neutral",
                      strength="weak", details="n/a", data={"k": 1})
    db.add_verdict(fp, "INCONCLUSIVE", 0.4, {"why": "no proof"})
    rep = finding_report(db, fp)
    assert rep["llm_review"]["verdict"] == "likely"
    assert rep["static_validation"][0]["outcome"] == "INCONCLUSIVE" and rep["static_validation"][0]["data"] == {"k": 1}
    assert rep["verdict"]["verdict"] == "INCONCLUSIVE" and rep["verdict"]["confidence_score"] == 0.4
    assert rep["status"] == "INCONCLUSIVE"
    with pytest.raises(ValueError):
        db.add_verdict(fp, "MAYBE", 0.5, {})


def test_metrics(db, tmp_path):
    repo = tmp_path / "r"
    write(repo, "SINK(a)\nSINK(b)\nSINK(c)\n")
    scan(db, repo, "c1")
    fps = [r["fingerprint"] for r in db.list_findings()]
    with pytest.raises(ValueError, match="never confirm alone"):
        db.add_verdict(fps[0], "CONFIRMED", 0.9, {}, basis="llm_only")
    db.add_verdict(fps[0], "CONFIRMED", 0.9, {}, basis="static")
    db.add_verdict(fps[1], "INCONCLUSIVE", 0.3, {})
    db.add_verdict(fps[1], "FALSE_POSITIVE", 0.1, {})        # latest verdict wins
    db.add_validation(fps[0], None, run_id="r", validator="static.secret_analysis", outcome="CONFIRMED",
                      signal="supports_real", strength="strong", details="")
    db.add_regression_draft(fps[0], model="m", path="d.txt", output={})
    m = db.metrics("o/r")
    assert m["findings_detected"] == 3 and m["confirmed"] == 1 and m["false_positives"] == 1
    assert m["inconclusive"] == 0 and m["validation_rate"] == 1.0
    assert m["regression_tests"]["llm_drafts"] == 1 and m["regression_tests"]["executed"] == 0
    assert m["statically_validated"] == 1
    assert m["scans"]["count"] == 1


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep missing")
def test_cli_real_semgrep_rescan_is_idempotent(tmp_path):
    root = tmp_path / "gsr"
    (root / "config").mkdir(parents=True)
    (root / "config" / "targets.yaml").write_text("targets: []\n")
    (root / "config" / "policies.yaml").write_text("scanners: {enabled: [semgrep]}\n")
    app = tmp_path / "vulnapp"
    shutil.copytree(FIXTURE, app)
    env = {**os.environ, "GSR_ROOT": str(root)}
    run = lambda *a: subprocess.run(["github-sec", *a], capture_output=True, text=True, env=env, timeout=600)
    r1, r2 = run("scan", "--path", str(app)), run("scan", "--path", str(app))
    assert r1.returncode == 0 and r2.returncode == 0, r1.stderr + r2.stderr
    j1 = json.loads(r1.stdout[:r1.stdout.index("\n}") + 2])
    j2 = json.loads(r2.stdout[:r2.stdout.index("\n}") + 2])
    assert j1["findings"] == j2["findings"] == 6 and j1["new"] == 6 and j2["new"] == 0
    db = Database(root / "data" / "gsr.db")
    assert db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 6


def test_skipped_scanner_does_not_mark_its_findings_gone(db, tmp_path):
    """Regression (2026-10-08): a scan where a scanner was not installed closed that scanner's findings."""
    class Missing(FakeScanner):
        def available(self):
            return False
    repo = tmp_path / "r"
    write(repo, "SINK(a)\n")
    scan(db, repo, "c1")
    s = scan_and_store(db, ScanTarget("o/r", repo, "c2"), [Missing()])
    assert s["scanners_skipped"] == {"fake": "not installed"}
    assert [r["state"] for r in db.list_findings(state=None)] == ["open"]
