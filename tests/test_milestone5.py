import json
import secrets
import shutil
import string
from pathlib import Path

import pytest

from github_security.analysis.findings import Finding
from github_security.pipeline import (draft_regression_test, finding_report, review_finding,
                                      scan_and_store, validate_finding)
from github_security.scanner import base as scanner_base
from github_security.scanner.base import Scanner, ScanTarget
from github_security.scanner.semgrep import SemgrepScanner
from github_security.storage.database import Database
from github_security.validation import static
from github_security.validation.static import StepResult
from github_security.validation.verdict import decide

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"
ALNUM = string.ascii_letters + string.digits


def rnd(n):
    return "".join(secrets.choice(ALNUM) for _ in range(n))


def F(**kw):
    base = {"id": "x", "repository": "o/r", "scanner": "semgrep", "rule": "r", "category": "sql-injection",
            "severity": "high", "scanner_confidence": 0.7, "file": "app.py", "line": 1, "end_line": 1,
            "evidence": "e"}
    return {**base, **kw}


# --- 2. non-production paths -------------------------------------------------

@pytest.mark.parametrize("path,np", [
    ("tests/test_api.py", True), ("pkg/server_test.go", True), ("src/testdata/x.go", True),
    ("examples/demo/main.go", True), ("web/a.spec.ts", True), ("docs/conf.py", True),
    ("src/app.py", False), ("cmd/git-sync/main.go", False), ("pkg/contest/x.go", False),
])
def test_non_production_path(tmp_path, path, np):
    r = static.non_production_path(tmp_path, F(file=path))
    assert (r.outcome == "FALSE_POSITIVE" and r.strength == "strong") == np


# --- 3. secrets -------------------------------------------------------------

def secret_step(tmp_path, line, category="secret"):
    (tmp_path / "s.py").write_text(f"x = 1\n{line}\n")
    return static.secret_analysis(tmp_path, F(file="s.py", line=2, end_line=2, category=category,
                                              scanner="gitleaks"))


def test_real_provider_token_confirmed_statically_without_storing_value(tmp_path):
    tok = "ghp_" + rnd(36)
    r = secret_step(tmp_path, f'TOKEN = "{tok}"')
    assert r.outcome == "CONFIRMED" and r.strength == "strong" and r.data["provider_format"] == "github_token"
    assert "liveness deliberately NOT tested" in r.details
    blob = json.dumps(r.__dict__)
    assert tok not in blob and tok[4:] not in blob and tok[4:14] not in blob


@pytest.mark.parametrize("line", [
    'API_KEY = "your-api-key-here"', 'TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
    'password = "changeme123"', 'secret: "${DB_PASSWORD}"', 'key = "{{ .Values.apiKey }}"',
    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"', 'token = "aaaaaaaaaaaaaaaaaaaaaaaa"',
])
def test_placeholders_are_false_positives(tmp_path, line):
    r = secret_step(tmp_path, line)
    assert r.outcome == "FALSE_POSITIVE" and r.data.get("placeholder"), r


def test_env_reference_is_false_positive(tmp_path):
    r = secret_step(tmp_path, 'TOKEN = os.environ.get("GITHUB_TOKEN_VALUE_FROM_VAULT")')
    assert r.outcome == "FALSE_POSITIVE" and r.data["env_reference"]


def test_generic_high_entropy_is_inconclusive(tmp_path):
    r = secret_step(tmp_path, f'session_secret = "{rnd(40)}"')
    assert r.outcome == "INCONCLUSIVE" and r.signal == "supports_real"


def test_low_entropy_value_leans_false_positive(tmp_path):
    r = secret_step(tmp_path, 'pwd = "hello2024"')
    assert r.outcome == "INCONCLUSIVE" and r.signal == "supports_false_positive"


def test_private_key_block(tmp_path):
    hdr = "-----BEGIN RSA " + "PRIVATE KEY-----"
    (tmp_path / "k.pem").write_text(f"{hdr}\n{rnd(64)}\n-----END RSA PRIVATE KEY-----\n")
    r = static.secret_analysis(tmp_path, F(file="k.pem", line=1, category="secret", scanner="gitleaks"))
    assert r.outcome == "CONFIRMED" and r.data["kind"] == "private_key"


def test_secret_step_skips_other_categories(tmp_path):
    assert static.secret_analysis(tmp_path, F()) is None


# --- 4. dependency usage ----------------------------------------------------

def dep(tmp_path, files: dict, evidence, manifest="requirements.txt"):
    for k, v in files.items():
        (tmp_path / k).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / k).write_text(v)
    return static.dependency_usage(tmp_path, F(category="vulnerable-dependency", scanner="osv",
                                               file=manifest, evidence=evidence))


def test_dependency_used_in_production(tmp_path):
    r = dep(tmp_path, {"requirements.txt": "pyyaml==5.1\n", "app/load.py": "import os\nimport yaml\n"},
            "PyPI:pyyaml==5.1")
    assert r.signal == "supports_real" and r.outcome == "INCONCLUSIVE"
    assert r.data["importing_files"] == ["app/load.py"] and "NOT established" in r.details


def test_dependency_only_in_tests_or_unused(tmp_path):
    r = dep(tmp_path, {"requirements.txt": "flask==2.0.0\n", "tests/test_x.py": "from flask import Flask\n"},
            "PyPI:flask==2.0.0")
    assert r.signal == "supports_false_positive" and r.data["production_importers"] == 0
    r2 = dep(tmp_path, {}, "PyPI:requests==2.0.0")
    assert r2.signal == "supports_false_positive" and "no direct import" in r2.details


def test_dependency_usage_scoped_to_manifest_subtree(tmp_path):
    r = dep(tmp_path, {"examples/requirements.txt": "flask==2.0.0\n", "app.py": "import flask\n"},
            "PyPI:flask==2.0.0", manifest="examples/requirements.txt")
    assert r.signal == "supports_false_positive" and r.data["search_scope"] == "examples"


def test_go_and_npm_usage(tmp_path):
    go = dep(tmp_path, {"go.mod": "require (\n\tgolang.org/x/net v0.1.0 // indirect\n)\n",
                        "pkg/a.go": 'import (\n\t"golang.org/x/net/http2"\n)\n'},
             "Go:golang.org/x/net==v0.1.0", manifest="go.mod")
    # post-scan fix: Go deps now report requirement (direct/indirect) + relation instead of go_indirect
    assert go.signal == "supports_real" and go.data["requirement"] == "indirect"
    assert go.data["relation"] == "imported"
    npm = dep(tmp_path, {"package-lock.json": "{}", "src/i.js": "const _ = require('lodash/fp')\n"},
              "npm:lodash==4.17.20", manifest="package-lock.json")
    assert npm.signal == "supports_real"


# --- 1. rule reproduction (real semgrep, parses only) -----------------------

@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep missing")
def test_rule_reproduction_and_fix(tmp_path):
    app = tmp_path / "app"
    shutil.copytree(FIXTURE, app)
    sg = SemgrepScanner()
    f = F(file="app.py", line=25, rule="gsr-py-sqli")
    r = static.rule_reproduction(app, f, {"semgrep": sg})
    assert r.signal == "supports_real" and r.data["reproduced"] and r.outcome == "INCONCLUSIVE"
    src = (app / "app.py").read_text().replace(
        """cur.execute(f"SELECT * FROM users WHERE name = '{name}'")""",
        """cur.execute("SELECT * FROM users WHERE name = ?", (name,))""")
    (app / "app.py").write_text(src)
    r2 = static.rule_reproduction(app, f, {"semgrep": sg})
    assert r2.signal == "supports_false_positive" and not r2.data["reproduced"]


# --- 5. verdict / score -----------------------------------------------------

S = lambda v, o, sig, st: StepResult(v, o, sig, st, "d")


def test_llm_alone_can_never_confirm():
    v = decide(F(), [S("static.rule_reproduction", "INCONCLUSIVE", "supports_real", "weak")],
               {"verdict": "confirmed", "confidence": 0.99})
    # decision-engine change: the score is no longer capped by the verdict (independent quantities)
    assert v.verdict == "INCONCLUSIVE" and v.basis == "none"
    assert v.rationale["executed_target_code"] is False and v.rationale["dynamic_proof"] is None
    assert v.quality == "strong_static"


def test_strong_static_fp_beats_llm():
    v = decide(F(), [S("static.non_production_path", "FALSE_POSITIVE", "supports_false_positive", "strong")],
               {"verdict": "confirmed", "confidence": 0.95})
    assert v.verdict == "FALSE_POSITIVE" and v.basis == "static"


def test_static_confirmation_survives_llm_disagreement():
    v = decide(F(category="secret"), [S("static.secret_analysis", "CONFIRMED", "supports_real", "strong")],
               {"verdict": "false_positive", "confidence": 0.9})
    assert v.verdict == "CONFIRMED" and v.basis == "static"
    assert any("LLM proposed FALSE_POSITIVE" in r for r in v.rationale["decision"]["human_review_reasons"])


def test_llm_false_positive_alone_is_inconclusive():
    # decision-engine change: the former "llm_only" FALSE_POSITIVE path is removed; the LLM can no
    # longer set the final verdict on its own, whatever its confidence.
    hi = decide(F(), [], {"verdict": "false_positive", "confidence": 0.99})
    lo = decide(F(), [], {"verdict": "false_positive", "confidence": 0.6})
    assert hi.verdict == lo.verdict == "INCONCLUSIVE"
    assert hi.rationale["decision"]["rule"] == "R4_LLM_CLAIM_WITHOUT_PROOF"


def test_score_is_separate_from_verdict():
    a = decide(F(scanner_confidence=0.7), [S("x", "INCONCLUSIVE", "supports_real", "weak")],
               {"verdict": "likely", "confidence": 0.8})
    b = decide(F(scanner_confidence=0.3), [S("x", "INCONCLUSIVE", "supports_false_positive", "weak")], None)
    assert a.verdict == b.verdict == "INCONCLUSIVE" and a.score > b.score
    assert decide(F(), [], None).verdict == "INCONCLUSIVE"


# --- 6. pipeline: statuses, evidence, no execution ------------------------

class FixtureScanner(Scanner):
    name = "semgrep"

    def available(self):
        return True

    def scan(self, t):
        return [Finding(repository=t.slug, commit=t.commit, file="config.py", line=2, rule="github-pat",
                        category="secret", severity="high", confidence=0.6, scanner="gitleaks",
                        description="d", evidence="github-pat match in config.py (value redacted)"),
                Finding(repository=t.slug, commit=t.commit, file="tests/test_x.py", line=1, rule="gsr-py-sqli",
                        category="sql-injection", severity="high", confidence=0.7, scanner="semgrep",
                        description="d", evidence="cur.execute(x)")]


@pytest.fixture
def stored(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "config.py").write_text(f'# cfg\nGITHUB = "ghp_{rnd(36)}"\n')
    (repo / "tests").mkdir()
    (repo / "tests" / "test_x.py").write_text("cur.execute(x)\n")
    db = Database(tmp_path / "g.db")
    scan_and_store(db, ScanTarget("local:repo", repo, "c1"), [FixtureScanner()])
    return db, repo, tmp_path / "evidence"


def test_validate_pipeline_states_and_evidence(stored, monkeypatch):
    db, repo, ev = stored
    calls = []
    real_run = scanner_base.subprocess.run
    monkeypatch.setattr(scanner_base.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or real_run(cmd, **kw))
    rows = {r["file"]: r for r in db.list_findings()}
    assert all(r["status"] == "DETECTED" for r in rows.values())

    sec = validate_finding(db, rows["config.py"]["id"], [], ev)
    tst = validate_finding(db, rows["tests/test_x.py"]["id"], [], ev)
    assert (sec["verdict"], sec["basis"]) == ("CONFIRMED", "static")
    assert (tst["verdict"], tst["basis"]) == ("FALSE_POSITIVE", "static")

    rep = finding_report(db, sec["id"])
    # CONFIRMED is never acted upon automatically: it is queued for a human
    assert rep["status"] == "READY_FOR_HUMAN_REVIEW" and rep["final_verdict"] == "CONFIRMED"
    assert rep["verdict"]["executed_target_code"] is False
    bundle = json.loads(Path(sec["evidence"]).read_text())
    assert bundle["pipeline"][2] == "EVIDENCE_ASSESSED" and "No target code was executed" in bundle["disclaimer"]
    secret_value = (repo / "config.py").read_text().split('"')[1]
    assert secret_value not in Path(sec["evidence"]).read_text()
    assert secret_value not in json.dumps([dict(r) for r in db.conn.execute("SELECT * FROM validations")])
    # no external process at all here (no scanners passed) => nothing could have been executed
    assert calls == []


def test_validation_never_runs_interpreters(tmp_path, monkeypatch):
    if not shutil.which("semgrep"):
        pytest.skip("semgrep missing")
    app = tmp_path / "app"
    shutil.copytree(FIXTURE, app)
    db = Database(tmp_path / "g.db")
    scan_and_store(db, ScanTarget("local:app", app, "c1"), [SemgrepScanner()])
    calls = []
    real_run = scanner_base.subprocess.run
    monkeypatch.setattr(scanner_base.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or real_run(cmd, **kw))
    fid = db.list_findings()[0]["id"]
    validate_finding(db, fid, [SemgrepScanner()], tmp_path / "ev")
    assert calls and all(Path(c[0]).name in {"semgrep", "gitleaks"} for c in calls)


def test_llm_confirmed_plus_validation_stays_inconclusive(stored):
    db, repo, ev = stored
    (repo / "app.py").write_text("x\n" * 30)
    fp = db.list_findings()[0]["fingerprint"]
    # simulate a finding in production code reviewed as "confirmed" by the LLM
    db.conn.execute("UPDATE findings SET file='app.py', line=5, category='sql-injection', scanner='semgrep' "
                    "WHERE fingerprint=?", (fp,))
    db.add_llm_review(fp, None, model="m", context_sha256="h",
                      output={"verdict": "confirmed", "confidence": 0.97}, duration_ms=1)
    r = validate_finding(db, fp, [], ev)
    assert r["verdict"] == "INCONCLUSIVE" and r["rule"] == "R4_LLM_CLAIM_WITHOUT_PROOF"


# --- 7. regression drafts are UNEXECUTED and never evidence ----------------

def test_regression_draft_is_unexecuted_and_not_evidence(stored, monkeypatch):
    db, repo, ev = stored
    fid = {r["file"]: r for r in db.list_findings()}["config.py"]["id"]
    before = validate_finding(db, fid, [], ev)

    def runner(system, prompt, schema, model=None):
        assert "REGRESSION UNIT TEST draft" in system
        return {"language": "python", "file_extension": "py", "code": "def test_x():\n    assert True\n",
                "what_it_checks": "w", "assumptions": ["a"]}
    out = draft_regression_test(db, fid, ev, runner=runner)
    p = Path(out["path"])
    assert out["status"] == "UNEXECUTED" and p.name.endswith(".txt") and "UNEXECUTED_DRAFT" in p.name
    assert p.read_text().startswith("# STATUS: UNEXECUTED - LLM-GENERATED DRAFT - NOT EVIDENCE")
    assert db.conn.execute("SELECT status FROM regression_drafts").fetchone()[0] == "UNEXECUTED"
    with pytest.raises(Exception):
        db.conn.execute("UPDATE regression_drafts SET status='PASSED'")
    after = validate_finding(db, fid, [], ev)
    assert (after["verdict"], after["confidence_score"]) == (before["verdict"], before["confidence_score"])
    m = db.metrics()
    assert m["regression_tests"]["llm_drafts"] == 1 and m["regression_tests"]["executed"] == 0
    assert finding_report(db, fid)["regression_drafts"][0]["status"] == "UNEXECUTED"
