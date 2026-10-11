"""Semgrep JSON parsing: raw data preserved in Finding.extra["semgrep"], fingerprints unchanged."""
import json
import math
from pathlib import Path

import pytest

from github_security.analysis.findings import Finding
from github_security.pipeline import scan_and_store
from github_security.scanner import semgrep as sg
from github_security.scanner.base import Scanner, ScannerError, ScanTarget
from github_security.storage.database import Database

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep" / "oss_1179_results.json"
GO_SRC = ('package main\n\nimport "database/sql"\n\nfunc h(db *sql.DB, id string) {\n'
          '\tdb.Query("SELECT * FROM t WHERE id = \'" + id + "\'")\n}\n\nfunc f() {\n\th := md5.New()\n}\n')
PY_SRC = "import sqlite3\n\n\ndef a(name):\n    cur.execute(f\"SELECT * FROM u WHERE n='{name}'\")\n"


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "main.go").write_text(GO_SRC)
    (r / "app.py").write_text(PY_SRC)
    return r


def load(repo: Path) -> dict:
    return json.loads(FIXTURE.read_text().replace("REPO", str(repo)))


def parse(repo, out=None, modes=None, slug="o/r"):
    return sg.parse_results(out if out is not None else load(repo), ScanTarget(slug, repo, "c1"), "semgrep",
                            modes if modes is not None else {})


def by_rule(findings):
    return {f.rule: f for f in findings}


# 1-2. full + short rule id -------------------------------------------------------------

def test_full_and_short_rule_id_preserved(repo):
    f = by_rule(parse(repo))
    s = f["tainted-sql-string"].extra["semgrep"]
    assert s["check_id"] == "go.lang.security.injection.tainted-sql-string.tainted-sql-string"
    assert s["rule_short_id"] == "tainted-sql-string" == f["tainted-sql-string"].rule
    assert f["use-of-md5"].extra["semgrep"]["check_id"].endswith("use_of_weak_crypto.use-of-md5")


def test_two_rules_with_same_short_id_are_distinguishable(repo):
    out = load(repo)
    twin = json.loads(json.dumps(out["results"][0]))
    twin["check_id"] = "go.aws-lambda.security.tainted-sql-string.tainted-sql-string"
    out["results"].append(twin)
    ids = {f.extra["semgrep"]["check_id"] for f in parse(repo, out) if f.rule == "tainted-sql-string"}
    assert len(ids) == 2


# 3. metavars ---------------------------------------------------------------------------

def test_metavars_kept_when_present_and_flagged_absent_otherwise(repo):
    out = load(repo)
    out["results"][0]["extra"]["metavars"] = {"$X": {"abstract_content": "id", "start": {"line": 6}}}
    f = by_rule(parse(repo, out))
    assert f["tainted-sql-string"].extra["semgrep"]["metavars"]["$X"]["abstract_content"] == "id"
    assert "metavars" not in f["tainted-sql-string"].extra["semgrep"]["not_provided_by_semgrep"]
    md5 = f["use-of-md5"].extra["semgrep"]
    assert md5["metavars"] is None and "metavars" in md5["not_provided_by_semgrep"]


# 4. positions --------------------------------------------------------------------------

def test_positions_preserved(repo):
    s = by_rule(parse(repo))["tainted-sql-string"].extra["semgrep"]
    assert s["start"] == {"line": 6, "col": 11, "offset": 98}
    assert s["end"] == {"line": 6, "col": 52, "offset": 139}


# 5. taint / dataflow information ---------------------------------------------------------

def test_rule_mode_known_only_for_local_rule_files(repo, tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yaml").write_text("rules:\n- id: gsr-py-sqli\n  mode: taint\n  languages: [python]\n"
                                  "  severity: ERROR\n  message: m\n  pattern-sources: []\n  pattern-sinks: []\n"
                                  "- id: plain\n  languages: [go]\n  severity: INFO\n  message: m\n  pattern: x\n")
    modes = sg.load_rule_modes([str(rules), "p/golang", "/does/not/exist"])
    assert modes == {"gsr-py-sqli": "taint", "plain": "search"}
    f = by_rule(parse(repo, modes=modes))
    py = f["gsr-py-sqli"].extra["semgrep"]
    assert (py["rule_mode"], py["rule_mode_source"]) == ("taint", "local rule file")
    go = f["tainted-sql-string"].extra["semgrep"]
    assert go["rule_mode"] is None and go["rule_mode_source"].startswith("unavailable")


def test_internal_rules_modes_are_loaded():
    modes = sg.load_rule_modes([str(sg.INTERNAL_RULES)])
    assert modes and all(m == "taint" for m in modes.values()) and "gsr-py-sqli" in modes


def test_dataflow_trace_kept_only_if_semgrep_provides_it(repo):
    f = by_rule(parse(repo))
    assert f["tainted-sql-string"].extra["semgrep"]["dataflow_trace"] is None
    assert "dataflow_trace" in f["tainted-sql-string"].extra["semgrep"]["not_provided_by_semgrep"]
    out = load(repo)
    trace = {"taint_source": ["CliLoc", [{"path": "main.go", "start": {"line": 5}}, "id"]],
             "intermediate_vars": [{"content": "q"}], "taint_sink": ["CliLoc", [{"path": "main.go"}, "db.Query"]]}
    out["results"][0]["extra"]["dataflow_trace"] = trace
    s = by_rule(parse(repo, out))["tainted-sql-string"].extra["semgrep"]
    assert s["dataflow_trace"]["intermediate_vars"] == [{"content": "q"}]


# 6. absent information, message, confidence, references ----------------------------------

def test_login_placeholders_not_stored_and_core_fields_kept(repo):
    s = by_rule(parse(repo))["tainted-sql-string"].extra["semgrep"]
    assert "lines" not in s and "fingerprint" not in s
    assert s["message"].startswith("User data flows") and s["confidence_raw"] == "HIGH"
    assert s["severity_raw"] == "ERROR" and s["engine_kind"] == "OSS"
    assert s["references"] == ["https://owasp.org/Top10/A03_2021-Injection"]
    assert s["metadata"]["interfile"] is True and s["metadata"]["likelihood"] == "HIGH"


def test_minimal_result_with_missing_optional_fields(repo):
    out = {"results": [{"check_id": "x.y.z", "path": str(repo / "main.go"), "start": {"line": 6}}]}
    f = parse(repo, out)[0]
    s = f.extra["semgrep"]
    assert f.end_line == 6 and s["end"] is None and s["start"] == {"line": 6, "col": None, "offset": None}
    assert s["metadata"] == {} and s["references"] == [] and s["message"] == ""
    assert f.category == "other" and f.confidence == 0.4 and f.severity == "medium"


# 7-8. no regression: fields + fingerprint identical to the previous parser --------------

def legacy_parse(r, repo, slug="o/r"):
    """Exact field computation of the parser before this change (reference implementation)."""
    extra = r.get("extra", {})
    meta = extra.get("metadata", {}) or {}
    rel = str(Path(r["path"]).relative_to(repo))
    line = int(r["start"]["line"])
    snippet = (repo / rel).read_text().splitlines()[line - 1][:300]
    refs = meta.get("references") or []
    return Finding(repository=slug, commit="c1", file=rel, line=line, end_line=int(r["end"]["line"]),
                   rule=r["check_id"].split(".")[-1], category=sg._category(meta, r["check_id"]),
                   severity=sg._SEV.get(str(meta.get("impact") or extra.get("severity", "")).upper(), "medium"),
                   confidence=sg._CONF.get(str(meta.get("confidence", "")).upper(), 0.4),
                   scanner="semgrep", description=extra.get("message", "")[:1000], evidence=snippet,
                   source=meta.get("gsr_source"), sink=meta.get("gsr_sink"),
                   references=[str(x) for x in (refs if isinstance(refs, list) else [refs])][:5])


def test_fields_and_fingerprints_identical_to_previous_parser(repo):
    out = load(repo)
    new = parse(repo, out)
    old = [legacy_parse(r, repo) for r in out["results"]]
    for a, b in zip(new, old):
        da, db_ = a.to_dict(), b.to_dict()
        da.pop("extra"); db_.pop("extra")
        assert da == db_
    md5 = by_rule(new)["use-of-md5"]
    assert md5.category == "weak-crypto" and md5.fingerprint == by_rule(old)["use-of-md5"].fingerprint


class FixtureScanner(Scanner):
    name = "semgrep"

    def __init__(self, repo, with_extra=True):
        self.repo, self.with_extra = repo, with_extra

    def available(self):
        return True

    def scan(self, t):
        fs = parse(self.repo, slug=t.slug)
        if not self.with_extra:
            for f in fs:
                f.extra = {}
        return fs


def test_existing_findings_upgrade_without_duplicates(repo, tmp_path):
    db = Database(tmp_path / "g.db")
    t = ScanTarget("o/r", repo, "c1")
    scan_and_store(db, t, [FixtureScanner(repo, with_extra=False)])        # stored before this change
    before = {r["id"]: r["fingerprint"] for r in db.list_findings()}
    s2 = scan_and_store(db, t, [FixtureScanner(repo)])
    after = {r["id"]: r for r in db.list_findings()}
    assert s2["new"] == 0 and set(after) == set(before)
    assert all(after[i]["fingerprint"] == fp for i, fp in before.items())
    md5 = [r for r in after.values() if r["rule"] == "use-of-md5"][0]
    assert json.loads(md5["extra"])["semgrep"]["check_id"].endswith("use-of-md5")
    s3 = scan_and_store(db, t, [FixtureScanner(repo)])
    assert s3["new"] == 0 and db.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3


# 9. unexpected / hostile values ----------------------------------------------------------

def test_unexpected_values_are_sanitised_or_skipped(repo):
    tok = "ghp_" + "A1b2C3d4" * 4 + "XYZW"
    out = {"results": [
        "not-a-dict",
        {"check_id": 123, "path": str(repo / "main.go"), "start": {"line": 6}},          # bad id
        {"check_id": "a.b", "path": None, "start": {"line": 6}},                         # bad path
        {"check_id": "a.b", "path": str(repo / "main.go"), "start": {"line": "x"}},      # bad line
        {"check_id": "a.b", "path": str(repo / "main.go"), "start": {"line": True}},     # bool line
        {"check_id": "go.x.weird", "path": str(repo / "main.go"),
         "start": {"line": 6, "col": "NaN", "offset": [1]}, "end": {"line": 2},           # end < start
         "extra": {"message": f"token {tok} " + "A" * 5000, "metadata": ["not", "a", "dict"],
                   "severity": {"nested": "obj"}, "metavars": {"$X": {"deep": {"a": {"b": {"c": {"d": 1}}}}},
                                                               "big": list(range(100)), "nan": math.nan},
                   "dataflow_trace": "not-a-dict", "lines": tok}},
    ]}
    fs = parse(repo, out)
    assert len(fs) == 1
    f = fs[0]
    s = f.extra["semgrep"]
    blob = json.dumps(f.to_dict())                                  # JSON-serialisable
    assert tok not in blob and len(s["message"]) <= 2000
    assert f.end_line == 6 and s["start"] == {"line": 6, "col": None, "offset": None}
    assert s["metadata"] == {} and s["dataflow_trace"] is None
    assert len(s["metavars"]["big"]) == 20 and s["metavars"]["nan"] is None
    assert s["metavars"]["$X"]["deep"]["a"]["b"]["c"] is None       # depth bounded
    assert f.category == "other"


def test_path_escaping_repository_still_refused(repo):
    out = {"results": [{"check_id": "a.b", "path": "/etc/passwd", "start": {"line": 1}}]}
    with pytest.raises(ScannerError):
        parse(repo, out)


def test_non_dict_output_yields_no_findings(repo):
    assert parse(repo, out=[]) == [] and parse(repo, out={"results": "x"}) == []
