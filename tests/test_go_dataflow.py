"""Go inter-procedural dataflow (static only): fixtures A–L, safety of the decision engine.

Fixtures under tests/fixtures/go_dataflow are synthetic and only parsed, never compiled or executed.
"""
import ast
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.analysis import go_dataflow as gd
from github_security.analysis.decision import decide
from github_security.analysis.evidence import EvidenceAssessment

FIX = Path(__file__).parent / "fixtures" / "go_dataflow"


def run(case, sources=(), sinks=("sink",), **kw):
    return gd.analyze_go_repository(FIX / case, sinks=sinks, sources=sources, **kw)


def chains(res):
    return {tuple(p.functions()) for p in res.paths if not p.truncated}


def reasons(res, function):
    return {n["reason"] for n in res.tainted_no_proof if n["function"] == function}


# --------------------------------------------------------------------------- A–E: resolvable paths

def test_a_same_function():
    res = run("a_same", sources=["Handler"])
    assert chains(res) == {("Handler",)}
    p = res.paths[0]
    assert (p.source.kind, p.source.file, p.source.line, p.source.detail) == \
        ("source_param", "main.go", 3, "param 0 (input)")
    assert (p.sink.kind, p.sink.line, p.sink.detail, p.depth) == ("sink_arg", 4, "sink arg 0", 0)
    assert p.status == "POTENTIAL"


def test_b_one_helper():
    res = run("b_helper", sources=["Handler"])
    assert chains(res) == {("Handler", "Process")}
    p = res.paths[0]
    assert [(s.kind, s.function, s.line) for s in p.steps] == [("call", "Handler", 4), ("param", "Process", 7)]
    assert p.sink.line == 8 and p.depth == 1


def test_c_two_helpers():
    res = run("c_two_helpers", sources=["Handler"])
    assert chains(res) == {("Handler", "Process", "Save")}
    assert res.paths[0].depth == 2


def test_d_multiple_files_and_packages():
    res = run("d_multi", sources=["Handler"])
    assert chains(res) == {("Handler", "Process", "Save")}
    p = res.paths[0]
    assert [s.file for s in p.steps if s.kind == "param"] == ["service/service.go", "repository/repository.go"]
    assert p.source.file == "handler/handler.go" and p.sink.file == "repository/repository.go"
    # concatenation "prefix:" + value keeps the flow; fmt.Println is external, not internal
    fmt = [c for c in res.calls if c.callee_text == "fmt.Println"][0]
    assert fmt.resolution == "no_proof" and "external" in fmt.reason


def test_e_methods_receiver_types():
    res = run("e_methods", sources=["Handler", "HandlerValue"])
    assert chains(res) == {("Handler", "Service.Process", "Repository.Save"),
                           ("HandlerValue", "Service.Process", "Repository.Save")}
    assert not any("Other.Process" in p.functions() for p in res.paths)
    keys = {c.callee for c in res.calls if c.callee_text == "s.Process"}
    assert keys == {".:app.Service.Process"}


# --------------------------------------------------------------------------- F–G: refused as ambiguous

def test_f_ambiguous_receiver_no_path():
    res = run("f_ambiguous", sources=["HandlerCall", "HandlerShadow", "HandlerGlobal", "HandlerCallIface"])
    # go-dataflow/4: `func pick(..) *A` proves the receiver type from the signature -> resolved
    assert chains(res) == {("HandlerCall", "A.Process")}
    assert reasons(res, "HandlerCallIface") == {"processor is an interface: dynamic dispatch not resolved"}
    assert reasons(res, "HandlerShadow") == {"receiver type ambiguous"}
    assert "package-level" in reasons(res, "HandlerGlobal").pop()


def test_g_interface_no_path():
    res = run("g_interface", sources=["HandlerParam", "HandlerVar", "HandlerFuncValue"])
    assert res.paths == []
    assert all("interface" in r for r in reasons(res, "HandlerParam") | reasons(res, "HandlerVar"))
    assert reasons(res, "HandlerFuncValue") == {"call through a local function value"}


# --------------------------------------------------------------------------- H–I: cycles, depth

def test_h_cycle_terminates():
    res = run("h_cycle", sources=["*"])
    assert ["A", "B", "A"] in res.cycles and ["Self", "Self"] in res.cycles
    assert ("A", "B") in chains(res)


def test_i_depth_limit_default_3():
    res = run("i_depth", sources=["A"])
    assert chains(res) == set()
    (t,) = res.paths
    assert t.truncated and t.sink is None and t.depth == 4
    assert t.functions() == ["A", "B", "C", "D", "E"]          # A->B->C->D analysed, E is cut


def test_i_depth_configurable():
    assert chains(run("i_depth", sources=["C"])) == {("C", "D", "E", "F")}   # exactly 3 hops
    assert chains(run("i_depth", sources=["A"], max_depth=5)) == {("A", "B", "C", "D", "E", "F")}
    res = run("i_depth", sources=["A"], max_depth=0)
    assert [p.functions() for p in res.paths] == [["A", "B"]] and res.paths[0].truncated
    with pytest.raises(ValueError):
        run("i_depth", max_depth=-1)


# --------------------------------------------------------------------------- J–L: false paths, propagation

def test_j_comments_and_strings_are_not_calls():
    res = run("j_comments", sources=["Handler"])
    assert res.paths == []
    assert [c.callee_text for c in res.calls if c.caller.endswith(".Handler")] == ["logLine", "len"]


def test_k_propagation():
    res = run("k_propagation", sources=["Chain", "Concat", "Clean", "UseBeforeAssign"])
    assert chains(res) == {("Chain", "Process"), ("Concat",)}
    chain = [p for p in res.paths if p.source.function == "Chain"][0]
    assert [s.detail for s in chain.steps if s.kind == "assign"] == ["x := input", "y := x"]


def test_l_external_call_not_internal():
    res = run("l_external", sources=["Handler", "Store"], sinks=("sink", "example.org/lib/store.Write"))
    assert chains(res) == {("Store",)}                          # import-path sink through alias `st`
    ext = [c for c in res.calls if c.callee_text == "extsvc.Process"][0]
    assert ext.resolution == "no_proof" and ext.callee is None and "github.com/ext/service" in ext.reason


def test_same_name_in_other_package_not_resolved_by_name():
    res = run("l_external", sinks=())
    assert all(c.callee is None for c in res.calls if c.caller.endswith("handler.Handler"))


# --------------------------------------------------------------------------- robustness

def test_parse_error_and_symlink_skipped(tmp_path):
    (tmp_path / "ok.go").write_text("package app\nfunc H(x string) { sink(x) }\nfunc sink(v string) {}\n")
    (tmp_path / "bad.go").write_text("package app\nfunc Broken(x string { sink(x)\n")
    (tmp_path / "link.go").symlink_to(FIX / "a_same" / "main.go")
    res = gd.analyze_go_repository(tmp_path, sinks=["sink"], sources=["H"])
    assert chains(res) == {("H",)}
    assert "bad.go" in res.parse_errors and "link.go" in res.skipped_files


def test_deterministic_and_serialisable():
    a = run("e_methods", sources=["*"]).to_dict()
    b = run("e_methods", sources=["*"]).to_dict()
    assert a == b and "body" not in str(a["functions"])


def test_path_budget():
    res = run("i_depth", sources=["*"], max_paths=1)
    assert len(res.paths) == 1 and res.budget_exhausted


# --------------------------------------------------------------------------- safety of the decision engine

def test_path_evidence_is_moderate_and_never_confirms():
    res = run("c_two_helpers", sources=["Handler"])
    ev = gd.path_to_evidence(res.paths[0])
    assert (ev.type, ev.strength, ev.supports) == ("SOURCE_TO_SINK", "moderate", True)
    for cat in ("command-injection", "sql-injection", "other"):
        d = decide(EvidenceAssessment("f1", cat, [ev]), llm_verdict="confirmed")
        assert d.final_verdict == "INCONCLUSIVE"
    trunc = run("i_depth", sources=["A"]).paths[0]
    assert gd.path_to_evidence(trunc) is None


def test_module_never_executes_anything():
    tree = ast.parse(Path(gd.__file__).read_text())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"subprocess", "socket", "urllib", "http", "requests", "ctypes", "multiprocessing"}
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not calls & {"system", "popen", "exec", "execv", "spawn"}


# --------------------------------------------------------------------------- Q: pointer dereference

def _ptr(entry):
    res = run("q_pointers", sources=[entry])
    return res, {r["reason"] for r in res.pointer_refusals if r["function"] == entry}


def test_q_deref_positive_through_variable():
    res, refused = _ptr("DerefVar")
    assert chains(res) == {("DerefVar",)} and not refused
    (p,) = res.paths
    assert [(s.kind, s.detail) for s in p.steps] == [("assign", "x := input"), ("deref", "*p -> x (p := &x)")]
    assert p.sink.detail == "sink arg 0" and p.status == "POTENTIAL"


def test_q_deref_value_reaches_sink_in_callee():
    res, _ = _ptr("DerefCall")
    assert chains(res) == {("DerefCall", "helper")}


@pytest.mark.parametrize("entry", ["OtherVar", "Reassigned", "PointeeKilled"])
def test_q_deref_proven_other_value_no_path(entry):
    res, refused = _ptr(entry)
    assert res.paths == [] and not refused and not res.tainted_no_proof


@pytest.mark.parametrize("entry,reason", [
    ("Ambiguous", "pointer p has several possible pointees (input, other)"),
    ("External", "pointer p not built by &x in this function (call_expression)"),
    ("Escaped", "pointer p escapes (used other than *p)"),
    ("WriteThrough", "write through pointer p"),
    ("ParamPointer", "pointer input comes from a parameter: pointee unknown"),
])
def test_q_deref_unprovable_identity_is_explicit_no_proof(entry, reason):
    res, refused = _ptr(entry)
    assert res.paths == []                       # never a guessed path
    assert refused == {reason}


# --------------------------------------------------------------------------- explicit field refusals

def test_alias_refusal_is_explicit():
    res = gd.analyze_go_repository(FIX / "bench" / "n06_aliasing", sinks=["sink"], sources=["Entry"])
    assert res.paths == []
    assert [(r["field"], r["reason"]) for r in res.field_refusals] == [("c.Cmd", "c is aliased in Entry")]


def test_nested_field_refusal_is_explicit():
    res = gd.analyze_go_repository(FIX / "bench" / "n08_unsupported_field", sinks=["sink"], sources=["Entry"])
    assert res.paths == []
    assert [(r["field"], r["reason"]) for r in res.field_refusals] == \
        [("c.In.Cmd", "nested access path not supported")]
