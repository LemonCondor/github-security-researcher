"""GoDataflow behaviour benchmark: one synthetic fixture per property, explicit expected outcome per case.

Measures the CURRENT behaviour of the component only; it says nothing about the security of any code.
Fixtures (tests/fixtures/go_dataflow/bench/<case>/main.go) are parsed by tree-sitter, never compiled or executed.
`sink` is an abstract placeholder function. Summary table: `python tests/test_go_dataflow_bench.py`.
"""
from collections import Counter
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.analysis import go_dataflow as gd

BENCH = Path(__file__).parent / "fixtures" / "go_dataflow" / "bench"

PATH, NO_PATH, NO_PROOF, TRUNCATED, UNSUPPORTED = "PATH", "NO_PATH", "NO_PROOF", "TRUNCATED", "UNSUPPORTED_CURRENTLY"

# case -> (category, expected, expected complete chain for PATH | None, known gap reason | None)
CASES = {
    "p01_param_var":              ("base flow", PATH, ("Entry",), None),
    "p02_param_other_func":       ("base flow", PATH, ("Entry", "helper"), None),
    "p03_pointer_pass":           ("pointers", PATH, ("Entry", "helper"), None),
    "p03b_pointer_deref":         ("pointers", PATH, ("Entry",), None),     # go-dataflow/5
    "p04_struct_field":           ("structs", PATH, ("Entry",), None),
    "p05_struct_by_value":        ("structs", PATH, ("Entry", "use"), None),
    "p06_struct_by_pointer":      ("structs", PATH, ("Entry", "use"), None),
    "p08_keyed_literal":          ("structs", PATH, ("Entry",), None),
    "p07_method_receiver":        ("methods/types", PATH, ("Entry", "Config.Run"), None),
    "p09_declared_return_type":   ("methods/types", PATH, ("Entry", "Service.Do"), None),
    "p10_reassign_kills":         ("precision", NO_PATH, None, None),
    "p11_shadowing":              ("precision", NO_PATH, None, None),
    "p12_cycle":                  ("termination", PATH, ("Entry", "a", "b"), None),
    "p13_depth_limit":            ("termination", TRUNCATED, None, None),
    "n01_two_structs_same_field": ("negative structs", NO_PATH, None, None),
    "n02_two_objects_same_type":  ("negative structs", NO_PATH, None, None),
    "n06_aliasing":               ("negative structs", NO_PROOF, None, None),   # explicit since go-dataflow/5
    "n08_unsupported_field":      ("negative structs", NO_PROOF, None, None),   # explicit since go-dataflow/5
    "n03_ambiguous_type":         ("negative resolution", NO_PROOF, None, None),
    "n04_ambiguous_interface":    ("negative resolution", NO_PROOF, None, None),
    "n05_call_result_untyped":    ("negative resolution", NO_PROOF, None, None),
    "n07_constant_before_sink":   ("negative syntax", NO_PATH, None, None),
    "n09_comment_or_string":      ("negative syntax", NO_PATH, None, None),
    "j01_json_body_struct":       ("json", UNSUPPORTED, None, None),
}


def analyze(case: str) -> gd.AnalysisResult:
    if case.startswith("j"):         # request body -> JSON decoder -> struct field -> function -> sink
        return gd.analyze_go_repository(BENCH / case, sinks=["sink"], http_sources=True)
    return gd.analyze_go_repository(BENCH / case, sinks=["sink"], sources=["Entry"])


def outcome(res: gd.AnalysisResult) -> str:
    if any(not p.truncated for p in res.paths):
        return PATH
    if res.paths:
        return TRUNCATED
    if res.tainted_no_proof or res.field_refusals or res.pointer_refusals:
        return NO_PROOF
    return NO_PATH


def matches(expected: str, actual: str) -> bool:
    if expected == UNSUPPORTED:      # capability absent: anything but a (complete or truncated) path
        return actual in (NO_PATH, NO_PROOF)
    return expected == actual


def _params():
    return [pytest.param(case, marks=[pytest.mark.xfail(strict=True, reason=gap)] if gap else [], id=case)
            for case, (_, _, _, gap) in CASES.items()]


def test_every_fixture_has_a_case():
    assert {d.name for d in BENCH.iterdir() if d.is_dir()} == set(CASES)


@pytest.mark.parametrize("case", _params())
def test_case(case):
    _, expected, chain, _ = CASES[case]
    res = analyze(case)
    assert res.parse_errors == []
    actual = outcome(res)
    assert matches(expected, actual), f"{case}: expected {expected}, got {actual}"
    if expected == PATH:
        assert {tuple(p.functions()) for p in res.paths if not p.truncated} == {chain}
        assert all(p.status == "POTENTIAL" for p in res.paths)


def test_cycle_is_recorded_and_terminates():
    assert ["Entry", "a", "b", "a"] in analyze("p12_cycle").cycles


def test_depth_limit_cuts_after_default_depth():
    (p,) = analyze("p13_depth_limit").paths
    assert p.truncated and p.sink is None and p.depth == gd.DEFAULT_MAX_DEPTH + 1


def test_refusal_reasons():
    def why(case):
        res = analyze(case)
        return {n["reason"] for n in res.tainted_no_proof} | {f["reason"] for f in res.field_refusals}
    assert why("n03_ambiguous_type") == {"receiver type ambiguous"}
    assert why("n04_ambiguous_interface") == {"Processor is an interface: dynamic dispatch not resolved"}
    assert why("n05_call_result_untyped") == {"receiver type unknown: result type any of makeAny unresolved"}
    # JSON: the request body stops at the external decoder; the struct field is never reached
    assert why("j01_json_body_struct") == {"external or unresolved package encoding/json"}


# --------------------------------------------------------------------------- measures

def summarize() -> tuple[dict, dict]:
    rows: dict[str, Counter] = {}
    total: Counter = Counter()
    for case, (cat, expected, _, _) in CASES.items():
        actual = outcome(analyze(case))
        ok = matches(expected, actual)
        c = Counter({k: int(v) for k, v in dict(cases=1, correct=ok,
                    missed_path=expected == PATH and actual != PATH,
                    false_path=expected != PATH and actual == PATH,
                    correct_refusal=expected in (NO_PATH, NO_PROOF) and ok,
                    unexpected_refusal=actual in (NO_PATH, NO_PROOF) and not ok,
                    truncated=actual == TRUNCATED,
                    unsupported=expected == UNSUPPORTED).items()})
        rows.setdefault(cat, Counter()).update(c)
        total.update(c)
    return rows, total


def test_summary_counts():
    _, t = summarize()
    assert (t["cases"], t["correct"], t["missed_path"], t["false_path"]) == (24, 24, 0, 0)
    assert (t["correct_refusal"], t["unexpected_refusal"], t["truncated"], t["unsupported"]) == (11, 0, 1, 1)


if __name__ == "__main__":
    cols = ["cases", "correct", "missed_path", "false_path", "correct_refusal", "unexpected_refusal",
            "truncated", "unsupported"]
    rows, total = summarize()
    print("| category | " + " | ".join(cols) + " |\n|" + "---|" * (len(cols) + 1))
    for name, c in list(rows.items()) + [("TOTAL", total)]:
        print(f"| {name} | " + " | ".join(str(c[k]) for k in cols) + " |")
