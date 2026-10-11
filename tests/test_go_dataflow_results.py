"""go-dataflow/4: receiver typing from DECLARED result types (signature only), cases 1-12.

Fixtures are synthetic Go code: parsed by tree-sitter, never compiled or executed.
"""
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.analysis import go_dataflow as gd

FIX = Path(__file__).parent / "fixtures" / "go_dataflow" / "p_results"
SOURCES = ["Ptr", "Val", "Method", "FieldToCallResult", "Chain", "OtherPkg", "Iface", "Dup", "Generic", "External",
           "Pair", "ErrFirst", "SelfType", "Deep"]


@pytest.fixture(scope="module")
def res():
    return gd.analyze_go_repository(FIX, sinks=["sink"], sources=SOURCES)


def complete(res):
    return {p.entry: p for p in res.paths if not p.truncated}


def refused(res, function):
    return {n["reason"] for n in res.tainted_no_proof if n["function"] == function}


@pytest.mark.parametrize("entry", ["Ptr",                 # 1. func returning *T
                                   "Val",                 # 2. func returning T
                                   "Method",              # 3. method returning *T
                                   "FieldToCallResult",   # 4. call -> result, struct field value -> sink
                                   "Chain",               # 5. call -> result -> method -> sink
                                   "Pair", "ErrFirst"])   # 10. result position followed
def test_resolved_through_declared_result(res, entry):
    p = complete(res)[entry]
    assert p.functions() == [entry, "Runner.Run"]
    assert (p.sink.file, p.sink.line) == ("app/app.go", 12)


def test_field_value_into_call_result_receiver(res):
    p = complete(res)["FieldToCallResult"]
    assert [s.detail for s in p.steps if s.kind == "assign"] == ["c.Command := input"]


def test_same_names_in_two_packages_not_confused(res):           # 6
    callees = {c.callee_text: c.callee for c in res.calls if c.callee_text.endswith(".Exec")}
    assert callees == {"a.NewRunner().Exec": "a:a.Runner.Exec", "b.NewRunner().Exec": "b:b.Runner.Exec"}
    p = complete(res)["OtherPkg"]
    assert p.sink.file == "a/a.go" and p.functions() == ["OtherPkg", "Runner.Exec"]
    assert [s.file for s in p.steps if s.kind == "param"] == ["a/a.go"]


def test_unprovable_results_are_no_proof(res):
    for entry in ("Iface", "Dup", "Generic", "External"):
        assert entry not in {p.entry for p in res.paths}, entry
    assert refused(res, "Iface") == {"Doer is an interface: dynamic dispatch not resolved"}                   # 7
    assert refused(res, "Dup") == {"receiver type unknown: result type: makeDup not uniquely declared in the "
                                   "package"}                                                                   # 8
    assert refused(res, "Generic") == {"result type: unsupported callee form index_expression"}                # 8
    assert refused(res, "External") == {"result type of external strings.NewReplacer unknown"}                 # 9


def test_self_returning_type_terminates_and_is_consistent(res):  # 11
    p = complete(res)["SelfType"]
    assert p.functions() == ["SelfType", "Node.Use"]


def test_depth_limit_still_applies(res):                          # 12
    (p,) = [p for p in res.paths if p.entry == "Deep"]
    assert p.truncated and p.depth == 4
    deep = gd.analyze_go_repository(FIX, sinks=["sink"], sources=["Deep"], max_depth=4)
    assert [q.functions() for q in deep.paths] == [["Deep", "Runner.Hop1", "Runner.Hop2", "Runner.Hop3",
                                                    "Runner.Hop4"]]


def test_returned_object_identity_still_refused_for_fields():
    """Typing a call result does not make its object trackable: field flows on it stay NO_PROOF."""
    res = gd.analyze_go_repository(FIX.parent / "n_structs", sinks=["sink"], sources=["UnknownObject"])
    assert res.paths == []
    assert {r["reason"] for r in res.field_refusals} == {"c obtained from an expression whose object identity "
                                                          "is unknown"}
