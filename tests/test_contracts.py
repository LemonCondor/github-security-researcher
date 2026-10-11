"""contracts.solidity/2 — fixture-driven precision tests (synthetic contracts only, nothing executed)."""
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_solidity")

from github_security.contracts import engine, run                     # noqa: E402
from github_security.contracts import slither_adapter                 # noqa: E402
from github_security.contracts.parser import parse_file               # noqa: E402
from github_security.contracts.rules import RULES, pragma_is_legacy   # noqa: E402
from github_security.engines.contract import ENGINE_STATUSES, DependencyMissing   # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "contracts"
MARK = re.compile(r"@expect\s+(SOL-[A-Z-]+)")
KNOWN_FN = re.compile(r"@known-fn\s+(SOL-[A-Z-]+)")
PAIRS = {  # rule -> (positive fixture, negative fixture(s))
    "SOL-REENTRANCY": ("reentrancy_pos.sol", ["reentrancy_neg.sol"]),
    "SOL-ACCESS-CONTROL": ("access_control_pos.sol", ["access_control_neg.sol"]),
    "SOL-TX-ORIGIN": ("tx_origin_pos.sol", ["tx_origin_neg.sol"]),
    "SOL-UNPROTECTED-INIT": ("initializer_pos.sol", ["initializer_neg.sol"]),
    "SOL-UNCHECKED-CALL": ("unchecked_call_pos.sol", ["unchecked_call_neg.sol"]),
    "SOL-DELEGATECALL-PARAM": ("delegatecall_pos.sol", ["delegatecall_neg.sol"]),
    "SOL-UNCHECKED-ARITH": ("arith_unchecked_pos.sol", ["arith_unchecked_neg.sol"]),
    "SOL-LEGACY-ARITH": ("arith_legacy_pos.sol", ["arith_legacy_neg.sol", "modern_arith_neg.sol"]),
}


def expected_set(marker=MARK) -> set:
    """Ground truth from `@expect RULE` markers, attributed to the enclosing function/modifier."""
    out = set()
    for p in sorted(FIX.glob("*.sol")):
        sf = parse_file(p, p.name)
        spans = [(fn.line, fn.end_line, c.name, fn.name) for c in sf.contracts
                 for fn in c.functions + list(c.modifiers.values())]
        for i, ln in enumerate(p.read_text().splitlines(), 1):
            for rule in marker.findall(ln):
                owner = [s for s in spans if s[0] <= i <= s[1]]
                assert owner, f"{p.name}:{i} marker outside a function"
                out.add((p.name, owner[0][2], owner[0][3], rule))
    return out


def actionable(report) -> set:
    return {(f["location"]["file"], f["location"]["contract"], f["location"]["function"], f["rule"])
            for f in report["findings"] if f["status"] != "FALSE_POSITIVE"}


@pytest.fixture(scope="module")
def corpus():
    return run(FIX)


def metrics(report):
    exp, known, got = expected_set(), expected_set(KNOWN_FN), actionable(report)
    rows = {}
    for rule in RULES:
        e = {x for x in exp if x[3] == rule}
        k = {x for x in known if x[3] == rule}
        g = {x for x in got if x[3] == rule}
        rows[rule] = {"TP": len(e & g), "FP": len(g - e - k), "FN": len(e - g), "known_FN": len(k - g)}
    return rows, exp, got


def test_metrics_table(corpus, capsys):
    rows, exp, got = metrics(corpus)
    with capsys.disabled():
        print("\nrule                      TP  FP  FN  known-FN")
        for rule, r in rows.items():
            print(f"{rule:24} {r['TP']:3} {r['FP']:3} {r['FN']:3} {r['known_FN']:5}")
    assert got - exp == set(), f"false positives: {sorted(got - exp)}"
    assert exp - got == set(), f"false negatives: {sorted(exp - got)}"
    assert all(r["TP"] >= 2 for r in rows.values())


def test_known_limits_are_still_missed(corpus):
    """Documented false negatives: if one starts being detected, move its marker to @expect."""
    known = expected_set(KNOWN_FN)
    assert known and not (known & actionable(corpus))


@pytest.mark.parametrize("rule", sorted(PAIRS))
def test_rule_positive_and_negative(rule):
    pos, negs = PAIRS[rule]
    assert any(f["rule"] == rule for f in run(FIX / pos)["findings"]), f"{rule} missed on {pos}"
    for neg in negs:
        hits = [f for f in run(FIX / neg)["findings"] if f["rule"] == rule]
        assert hits == [], f"{rule} fired on safe fixture {neg}: {[h['location'] for h in hits]}"


def test_finding_contract(corpus):
    assert corpus["parse_errors"] == []
    assert corpus["findings"]
    for f in corpus["findings"]:
        assert f["status"] in ENGINE_STATUSES and f["status"] != "CONFIRMED"
        assert f["status"] in ("CANDIDATE", "NEEDS_REVIEW")      # suppressed hits not included by default
        assert set(f["location"]) == {"file", "line", "contract", "function"} and f["location"]["line"] > 0
        assert f["tool"]["name"] and f["tool"]["version"] and "tree-sitter-solidity" in f["tool"]["parser"]
        assert f["evidence"] and all(e["kind"] == "code" and e["detail"] for e in f["evidence"])
        assert f["limitations"] and f["validation_method"] == "ast" and 0 < f["confidence"] < 1
        assert f["category"] == RULES[f["rule"]][0]
    json.dumps(corpus)                                     # JSON-serialisable report
    assert set(corpus["coverage"]) == {"implemented", "documented_only", "assumptions"}
    assert set(corpus["coverage"]["implemented"]) == set(RULES)


def test_suppressed_hits_are_false_positive_with_negative_evidence():
    rep = run(FIX / "reentrancy_neg.sol", include_suppressed=True)
    guarded = [f for f in rep["findings"] if f["location"]["function"] == "withdrawGuarded"
               and f["rule"] == "SOL-REENTRANCY"]
    assert len(guarded) == 1 and guarded[0]["status"] == "FALSE_POSITIVE"
    neg = [e for e in guarded[0]["evidence"] if e["kind"] == "negative"]
    assert neg and "nonReentrant" in neg[0]["detail"] and neg[0]["strength"] == "moderate"
    rep = run(FIX / "unchecked_call_neg.sol", include_suppressed=True)
    assert rep["findings"] and all(f["status"] == "FALSE_POSITIVE" for f in rep["findings"])
    assert all(e["strength"] == "strong" for f in rep["findings"] for e in f["evidence"] if e["kind"] == "negative")


def test_interface_callback_reentrancy_is_needs_review(corpus):
    f = [f for f in corpus["findings"] if f["location"]["function"] in ("payoutHook", "redeem")
         and f["rule"] == "SOL-REENTRANCY"]
    assert len(f) == 2 and all(x["status"] == "NEEDS_REVIEW" for x in f)


def test_arith_rules_are_never_candidate(corpus):
    for f in corpus["findings"]:
        if f["rule"] in ("SOL-UNCHECKED-ARITH", "SOL-LEGACY-ARITH"):
            assert f["status"] == "NEEDS_REVIEW"


@pytest.mark.parametrize("pragma,legacy", [
    ("^0.7.6", True), ("0.6.12", True), (">=0.6.0 <0.8.0", True), ("~0.7.0", True), ("<=0.7.6", True),
    ("^0.8.0", False), (">=0.7.0", False), (">=0.7.0 <0.9.0", False), ("0.8.19", False), ("", False),
])
def test_pragma_legacy(tmp_path, pragma, legacy):
    p = tmp_path / "P.sol"
    p.write_text((f"pragma solidity {pragma};\n" if pragma else "") + "contract P {}\n")
    assert pragma_is_legacy(parse_file(p)) is legacy


def test_parse_errors_reported_not_fatal(tmp_path):
    (tmp_path / "Broken.sol").write_text("pragma solidity ^0.8.0;\ncontract B { function f( external { x = ; }\n")
    rep = run(tmp_path)
    assert rep["parse_errors"] == ["Broken.sol"]


def test_symlink_outside_tree_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "X.sol").write_text("pragma solidity ^0.8.0; contract X { address owner; "
                                   "function setOwner(address o) external { owner = o; } }")
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "link.sol").symlink_to(outside / "X.sol")
    assert engine.collect_files(scan) == []


def test_skips_dependency_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dep.sol").write_text("contract Dep {}")
    (tmp_path / "A.sol").write_text("contract A {}")
    assert [p.name for p in engine.collect_files(tmp_path)] == ["A.sol"]


# ---------------------------------------------------------------- optional Slither adapter
def test_slither_absent_raises_dependency_missing(monkeypatch):
    monkeypatch.setattr(slither_adapter.shutil, "which", lambda _: None)
    with pytest.raises(DependencyMissing):
        slither_adapter.run_slither(str(FIX))


def test_slither_json_mapping_never_confirmed():
    data = {"results": {"detectors": [
        {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium", "description": "Reentrancy in A.w()",
         "elements": [{"type": "function", "name": "w", "source_mapping": {"filename_relative": "A.sol", "lines": [7]},
                       "type_specific_fields": {"parent": {"name": "A"}}}]},
        {"check": "solc-version", "impact": "Informational", "confidence": "High", "description": "old solc",
         "elements": []},
        {"check": "weak-prng", "impact": "High", "confidence": "Low", "description": "prng", "elements": []},
    ]}}
    fs = slither_adapter.map_slither_json(data, "x", "0.10.0")
    assert [f.status for f in fs] == ["CANDIDATE", "OBSERVATION", "NEEDS_REVIEW"]
    assert fs[0].location == {"file": "A.sol", "line": 7, "contract": "A", "function": "w"}
    assert fs[0].tool == {"name": "slither", "version": "0.10.0"} and fs[0].validation_method == "tool"
