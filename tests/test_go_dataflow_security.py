"""GoDataflow security integration (static only): scopes/reassignment, security sinks/sources,
neutralisations, synthetic evaluation, scanner findings, pipeline evidence and decision safety.

Fixtures are synthetic Go code: parsed by tree-sitter, never compiled or executed.
"""
import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.ai.prompts import build_user_prompt
from github_security.analysis import go_dataflow as gd
from github_security.analysis.context import build_context
from github_security.pipeline import scan_and_store, validate_finding
from github_security.scanner.base import ScanTarget
from github_security.scanner.go_dataflow import GoDataflowScanner, findings_from_result
from github_security.storage.database import Database

FIX = Path(__file__).parent / "fixtures" / "go_dataflow"
EVAL = FIX / "eval_app"


@pytest.fixture(scope="module")
def sec():
    return gd.analyze_security(EVAL)


def by_entry(res):
    return {p.entry: p for p in res.paths if not p.truncated}


# --------------------------------------------------------------------------- scopes / reassignment (audit fixes)

def test_scopes_reassignment_and_shadowing():
    res = gd.analyze_go_repository(FIX / "m_scopes", sinks=["sink", "sinkInt"], sources=["*"])
    entries = {p.entry for p in res.paths}
    assert entries == {"BranchReassign", "ShadowSame", "PlusAssign", "IfInit", "Range", "Helper", "Multi",
                       "SelfReferential"}   # self-referential receiver typing terminates
    # killed / out of scope / later definition / non-carrying results: no path
    for name in ("Reassigned", "ParamKilled", "ShadowSibling", "LoopCarried", "RangeIndex", "MultiOther"):
        assert name not in entries
    helper = by_entry(res)["Helper"]
    assert [s.kind for s in helper.steps][:3] == ["summary_call", "summary_param", "return"]


def test_sources_are_never_implicit():
    res = gd.analyze_go_repository(FIX / "m_scopes", sinks=["sink"])
    assert res.paths == []                       # string parameters are not user input by default
    res = gd.analyze_go_repository(FIX / "m_scopes", sinks=["sink"], sources=["Multi#0"])
    assert {p.entry for p in res.paths} == {"Multi"}


# --------------------------------------------------------------------------- security sinks and sources

def test_true_sql_http_helper_service_repository_interfile(sec):
    p = by_entry(sec)["Server.GetUser"]
    assert p.category == "sql-injection"
    assert p.functions() == ["Server.GetUser", "UserService.Lookup", "Repo.FindByName"]
    assert p.files() == ["api/handlers.go", "service/user.go", "repository/repo.go"]
    assert (p.source.kind, p.source.function, p.source.line) == ("source_expr", "userName", 34)
    assert (p.sink.file, p.sink.line, p.sink.detail) == ("repository/repo.go", 14, "database/sql.DB.Query arg 0")
    kinds = [s.kind for s in p.steps]
    assert "return" in kinds and kinds.count("propagate") == 2    # strings.TrimSpace + fmt.Sprintf


def test_parameterized_sql_is_not_a_path(sec):
    assert "Server.GetUserSafe" not in by_entry(sec)
    assert any(n["call"] == "r.db.Query" and n["arg"] == 1 for n in sec.neutralized)


def test_command_flow_shell_c_only(sec):
    p = by_entry(sec)["RunTool"]
    assert p.category == "command-injection" and p.functions() == ["RunTool", "runShell"]
    assert p.sink.detail == "os/exec.Command arg 2"
    assert "ListBranch" not in by_entry(sec) and "Uptime" not in by_entry(sec)   # fixed program / constant
    assert any(n["function"] == "ListBranch" for n in sec.neutralized)


def test_file_and_http_sinks(sec):
    assert by_entry(sec)["Server.Download"].category == "path-traversal"
    f = by_entry(sec)["Fetch"]
    assert f.category == "ssrf" and f.source.detail.startswith("http request: r.Header.Get")


def test_interface_ambiguity_and_neutralisations(sec):
    entries = by_entry(sec)
    assert "Server.Search" not in entries
    assert any("interface" in n["reason"] for n in sec.tainted_no_proof if n["function"] == "Server.Search")
    assert "Reset" not in entries                # x = "status" before the sink
    assert "Server.Page" not in entries          # strconv.Atoi does not propagate


def test_synthetic_evaluation_metrics(sec):
    expected = {"Server.GetUser": "sql-injection", "RunTool": "command-injection",
                "Server.Download": "path-traversal", "Fetch": "ssrf", "SubmitJob": "command-injection"}
    must_not = {"Server.GetUserSafe", "ListBranch", "Uptime", "Server.Search", "Reset", "Server.Page",
                "LabelJob", "ResetJob"}
    got = {e: p.category for e, p in by_entry(sec).items()}
    metrics = {"detected": len(got), "valid": sum(got.get(e) == c for e, c in expected.items()),
               "false_positives": len(set(got) & must_not),
               "refused": len([n for n in sec.tainted_no_proof if "external" not in (n["reason"] or "")]),
               "neutralized": len(sec.neutralized)}
    assert metrics == {"detected": 5, "valid": 5, "false_positives": 0, "refused": 1, "neutralized": 2}


# --------------------------------------------------------------------------- scanner + pipeline

def test_scanner_findings_structure(sec, tmp_path):
    findings, stats = findings_from_result(sec, ScanTarget("local:evalapp", EVAL, "c1"))
    assert {f.category for f in findings} == {"sql-injection", "command-injection", "path-traversal", "ssrf"}
    sql = next(f for f in findings if f.category == "sql-injection")
    assert (sql.scanner, sql.rule, sql.file, sql.line) == ("go_dataflow", "go-dataflow.sql-injection",
                                                           "repository/repo.go", 14)
    gdx = sql.extra["go_dataflow"]
    assert gdx["status"] == "POTENTIAL" and gdx["crosses_files"] and gdx["paths"][0]["depth"] == 2
    assert "not confirmed" in sql.description
    assert stats["findings"] == 5


def test_scanner_skips_non_production_paths(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(EVAL, repo / "examples" / "app")
    findings, stats = findings_from_result(gd.analyze_security(repo), ScanTarget("local:x", repo, "c"))
    assert findings == [] and stats["skipped_non_production"] == 5


@pytest.fixture
def stored(tmp_path):
    repo = tmp_path / "evalapp"
    shutil.copytree(EVAL, repo)
    db = Database(tmp_path / "gsr.db")
    scan_and_store(db, ScanTarget("local:evalapp", repo, "c1"), [GoDataflowScanner()])
    return db, tmp_path


def test_pipeline_evidence_is_source_to_sink_moderate_and_never_confirmed(stored):
    db, tmp = stored
    rows = db.conn.execute("SELECT id, fingerprint, category FROM findings").fetchall()
    assert len(rows) == 5
    for r in rows:
        # even with an LLM claiming "confirmed" at high confidence
        db.add_llm_review(r["fingerprint"], None, model="m", context_sha256="h",
                          output={"verdict": "confirmed", "confidence": 0.99}, duration_ms=1)
        out = validate_finding(db, r["id"], [GoDataflowScanner()], tmp / "evidence")
        assert out["verdict"] == "INCONCLUSIVE"
        bundle = json.loads(Path(out["evidence"]).read_text())
        s2s = [e for e in bundle["evidence"] if e["type"] == "SOURCE_TO_SINK"]
        assert len(s2s) == 1 and s2s[0]["strength"] == "moderate" and s2s[0]["source"] == "static.go_dataflow"
        assert s2s[0]["status"] == "VERIFIED" and s2s[0]["data"]["paths"][0]["status"] == "POTENTIAL"
        assert not any(e["type"] == "STATIC_DATAFLOW" for e in bundle["evidence"])   # reproduced
        assert bundle["decision"]["executed_target_code"] is False


def test_pipeline_triage_does_not_skip_llm(stored):
    db, tmp = stored
    fid = db.conn.execute("SELECT id FROM findings LIMIT 1").fetchone()[0]
    pre = validate_finding(db, fid, [GoDataflowScanner()], tmp / "evidence", triage=True)
    assert pre["decisive"] is False                  # R3 not met => goes on to contextual review


def test_path_no_longer_reproduced_is_negative_evidence(stored):
    db, tmp = stored
    r = db.conn.execute("SELECT id FROM findings WHERE category='ssrf'").fetchone()
    (tmp / "evalapp" / "api" / "handlers.go").write_text(
        (tmp / "evalapp" / "api" / "handlers.go").read_text().replace('r.Header.Get("X-Target")', '"fixed"'))
    out = validate_finding(db, r["id"], [GoDataflowScanner()], tmp / "evidence")
    bundle = json.loads(Path(out["evidence"]).read_text())
    assert out["verdict"] == "INCONCLUSIVE"
    assert any(e["type"] == "NEGATIVE_EVIDENCE" and e["source"] == "static.go_dataflow" for e in bundle["evidence"])


def test_llm_context_carries_verifiable_path(stored):
    db, tmp = stored
    f = dict(db.conn.execute("SELECT * FROM findings WHERE category='sql-injection'").fetchone())
    ctx = build_context(tmp / "evalapp", f)
    assert [s["kind"] for s in ctx.dataflow][0] == "source_expr" and ctx.dataflow[-1]["kind"] == "sink_arg"
    visible = ctx.visible_lines()
    assert all((s["file"], s["line"]) in visible for s in ctx.dataflow)   # every step can be cited
    prompt = build_user_prompt(ctx)
    assert 'kind="go_dataflow_path"' in prompt and "Do not add, move or invent steps" in prompt


# --------------------------------------------------------------------------- struct fields (engine go-dataflow/3)

STRUCT_SOURCES = ["FieldDirect", "PassValue", "PassPointer", "Literal", "TwoTypes", "UnknownObject", "AmbiguousType",
                  "Aliased", "FieldKilled", "ObjectReplaced", "FieldBranch", "OtherObject", "ViaInterfaceParam",
                  "Comments", "Cycle", "Deep"]


@pytest.fixture(scope="module")
def structs():
    return gd.analyze_go_repository(FIX / "n_structs", sinks=["sink"], sources=STRUCT_SOURCES)


def test_struct_true_flows(structs):
    got = {p.entry: p.functions() for p in structs.paths if not p.truncated}
    assert got["FieldDirect"] == ["FieldDirect"]                                  # 1. field -> sink
    assert got["PassValue"] == ["PassValue", "serviceValue"]                      # 2. struct by value
    assert got["PassPointer"] == ["PassPointer", "servicePtr"]                    # 3. pointer to struct
    assert got["Literal"] == ["Literal", "Config.Run"]                            # keyed literal + receiver
    assert got["FieldBranch"] == ["FieldBranch"]                                  # 7. branch: may flow
    hop = next(p for p in structs.paths if p.entry == "PassPointer")
    assert [s.detail for s in hop.steps if s.kind in ("call", "param")] == \
        ["servicePtr(arg 0: c.Command)", "param 0 (c).Command"]
    assert [s.detail for s in hop.steps if s.kind == "assign"] == ["c.Command = input"]


def test_struct_negative_cases_have_no_path(structs):
    entries = {p.entry for p in structs.paths}
    for name in ("TwoTypes",            # 4. same field name on another type / other field of the object
                 "OtherObject",         # 8. other object of the same type
                 "FieldKilled", "ObjectReplaced",   # 6. constant / new object before the sink
                 "Comments",            # 10. comment / string
                 "UnknownObject", "AmbiguousType", "Aliased", "ViaInterfaceParam"):
        assert name not in entries, name


def test_struct_refusals_are_no_proof(structs):
    reasons = {(r["function"], r["reason"]) for r in structs.field_refusals}
    assert ("AmbiguousType", "receiver type ambiguous") in reasons                # 5. ambiguous type
    # object from a call: type now proven by the signature, identity still unknown -> refused
    assert ("UnknownObject", "c obtained from an expression whose object identity is unknown") in reasons
    assert ("Aliased", "c is aliased in Aliased") in reasons
    iface = [n for n in structs.tainted_no_proof if n["function"] == "ViaInterfaceParam"]
    assert iface and "Runner" in iface[0]["reason"]                               # 9. interface


def test_struct_cycle_and_depth(structs):
    assert ["Cycle", "cycleA", "cycleB", "cycleA"] in structs.cycles              # 11. terminates
    deep = [p for p in structs.paths if p.entry == "Deep"]
    assert len(deep) == 1 and deep[0].truncated and deep[0].depth == 4            # 12. default limit 3
    res = gd.analyze_go_repository(FIX / "n_structs", sinks=["sink"], sources=["Deep"], max_depth=4)
    assert [p.functions() for p in res.paths if not p.truncated] == [["Deep", "d1", "d2", "d3", "d4"]]


def test_struct_eval_app_flow_crosses_files(sec):
    p = by_entry(sec)["SubmitJob"]
    assert p.category == "command-injection" and p.sink.detail == "os/exec.Command arg 2"
    assert p.files() == ["api/jobs.go", "service/jobs.go"]


def test_operator_inputs_are_diagnostics_only(tmp_path):
    repo = FIX / "o_operator"
    assert gd.analyze_security(repo).paths == []                                  # never a scanner source
    diag = gd.analyze_operator_diagnostics(repo)
    assert {p.source.kind for p in diag.paths} == {"source_operator"}
    assert sorted(tuple(p.functions()) for p in diag.paths) == [("main",), ("main", "syncer.run")]
    findings, _ = findings_from_result(diag, ScanTarget("local:o", repo, "c"))
    assert findings == []                                                          # scanner rejects them
