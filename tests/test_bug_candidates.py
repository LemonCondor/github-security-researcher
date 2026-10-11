"""Ordinary bug candidates (Go, static only): positive / negative / ambiguous fixtures per category,
deterministic status rules, strict LLM review contract, separation from the security pipeline.

Fixtures under tests/fixtures/bugs are synthetic and only parsed, never compiled or executed. No live LLM call.
"""
import ast
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.analysis.findings import CATEGORIES, STATUSES
from github_security.bugs import model as bm
from github_security.bugs.go_detectors import detect_go_bugs
from github_security.bugs.review import OUTPUT_SCHEMA, build_prompt, build_snippets, review_candidate

FIX = Path(__file__).parent / "fixtures" / "bugs"


def by_function(case):
    return {c.function: c for c in detect_go_bugs(FIX / case)}


# --------------------------------------------------------------------------- ignored-error

def test_ignored_error_positive():
    got = by_function("ignored_error")
    for fn, line in (("Persist", 23), ("Close", 28)):
        c = got[fn]
        assert (c.file, c.line, c.category, c.status) == ("positive.go", line, "ignored-error", bm.BUG_CANDIDATE)
        assert not c.negative_evidence and not c.ambiguity
    assert "save (declared at positive.go:7)" in got["Persist"].suspicion
    assert "Store.flush" in got["Close"].suspicion


def test_ignored_error_negative():
    got = by_function("ignored_error")
    assert not {"PersistChecked", "PersistForward", "Log"} & set(got)       # checked / returned / external
    t = got["Touch"]                                                       # looks ignored, cannot fail
    assert t.status == bm.FALSE_POSITIVE
    assert t.negative_evidence == ["touch returns a literal nil error in all 1 return statement(s)"]


def test_ignored_error_ambiguous_needs_review():
    got = by_function("ignored_error")
    assert got["PersistBestEffort"].status == bm.NEEDS_REVIEW
    assert got["PersistBestEffort"].ambiguity == ["explicit discard `_ =`: may be deliberate"]
    assert got["PersistDeferred"].status == bm.NEEDS_REVIEW and "defer" in got["PersistDeferred"].ambiguity[0]
    assert got["Shutdown"].status == bm.NEEDS_REVIEW and "Close" in got["Shutdown"].ambiguity[0]   # teardown
    assert got["Close"].status == bm.BUG_CANDIDATE          # a FUNCTION named Close calling flush is not teardown


# --------------------------------------------------------------------------- overwritten-error

def test_overwritten_error_positive():
    got = by_function("overwritten_error")
    assert (got["Run"].line, got["Run"].related_lines, got["Run"].status) == (21, [21, 22], bm.BUG_CANDIDATE)
    assert (got["RunPair"].related_lines, got["RunPair"].status) == ([28, 29], bm.BUG_CANDIDATE)
    assert "overwritten at line 22 with no read in between" in got["Run"].suspicion


def test_overwritten_error_negative():
    got = by_function("overwritten_error")
    assert not {"RunChecked", "RunWrapped", "RunShadow"} & set(got)       # read / wrapped / other variable
    n = got["RunNeverFails"]
    assert n.status == bm.FALSE_POSITIVE and n.negative_evidence[0].startswith("ok returns a literal nil")


def test_overwritten_error_ambiguous_needs_review():
    got = by_function("overwritten_error")
    assert got["RunClosure"].status == bm.NEEDS_REVIEW and "closure" in got["RunClosure"].ambiguity[0]
    assert got["RunGoto"].status == bm.NEEDS_REVIEW and "goto" in got["RunGoto"].ambiguity[0]


def test_exact_candidate_sets():
    """No extra candidate anywhere in the fixtures (precision)."""
    assert sorted((c.file, c.line) for c in detect_go_bugs(FIX / "ignored_error")) == \
        [("ambiguous.go", 5), ("ambiguous.go", 10), ("ambiguous.go", 19), ("negative.go", 24), ("positive.go", 23),
         ("positive.go", 28)]
    assert sorted((c.file, c.line) for c in detect_go_bugs(FIX / "overwritten_error")) == \
        [("ambiguous.go", 5), ("ambiguous.go", 14), ("negative.go", 36), ("positive.go", 21), ("positive.go", 28)]


def test_candidate_keeps_required_fields_and_is_deterministic():
    c = by_function("ignored_error")["Persist"]
    d = c.to_dict()
    for k in ("file", "line", "category", "explanation", "snippet", "suspicion", "negative_evidence",
              "confidence", "status", "status_reason", "fingerprint"):
        assert d[k] not in (None, "") or k == "negative_evidence"
    assert "   23 | \tsave(path)" in c.snippet and c.snippet_line().strip() == "save(path)"
    assert 0 < c.confidence < 1
    assert [x.to_dict() for x in detect_go_bugs(FIX / "ignored_error")] == \
        [x.to_dict() for x in detect_go_bugs(FIX / "ignored_error")]


def test_security_fixtures_give_no_spurious_candidates():
    """The GoDataflow fixtures contain no discarded error: the detectors must stay silent there."""
    for case in ("a_same", "e_methods", "eval_app", "n_structs", "p_results"):
        assert detect_go_bugs(FIX.parent / "go_dataflow" / case) == []


# --------------------------------------------------------------------------- status rules

def _cand(**kw):
    base = dict(file="a.go", line=1, category="ignored-error", rule="r", function="F", explanation="e",
                suspicion="s", snippet="    1 | f()", confidence=0.5)
    return bm.BugCandidate(**{**base, **kw})


def test_decide_rules():
    good = {"verdict": bm.LIKELY_BUG, "lines": [{"file": "a.go", "line": 1}]}
    assert bm.decide(_cand())[0] == bm.BUG_CANDIDATE
    assert bm.decide(_cand(), good)[0] == bm.LIKELY_BUG
    assert bm.decide(_cand(), {"verdict": bm.FALSE_POSITIVE, "lines": []})[0] == bm.NEEDS_REVIEW   # LLM can't dismiss
    assert bm.decide(_cand(), {"verdict": bm.NEEDS_REVIEW, "lines": []})[0] == bm.NEEDS_REVIEW
    assert bm.decide(_cand(negative_evidence=["x"]), good)[0] == bm.FALSE_POSITIVE              # facts win
    assert bm.decide(_cand(ambiguity=["x"]), good)[0] == bm.NEEDS_REVIEW
    with pytest.raises(ValueError):
        _cand(category="sql-injection")


def test_bug_statuses_are_separate_from_security_verdicts():
    assert not set(bm.BUG_STATUSES) & {"CONFIRMED", "INCONCLUSIVE"}
    assert not set(bm.BUG_CATEGORIES) & set(CATEGORIES)
    assert "LIKELY_BUG" not in STATUSES and "CONFIRMED" not in bm.BUG_STATUSES


# --------------------------------------------------------------------------- LLM review contract

def _runner(answer):
    seen = {}

    def run(system, prompt, schema, model=None):
        seen.update(system=system, prompt=prompt, schema=schema)
        return dict(answer)
    return run, seen


def test_review_prompt_contains_code_trigger_and_fenced_context():
    c = by_function("ignored_error")["Persist"]
    snips = build_snippets(FIX / "ignored_error", c)
    assert [(s["kind"], s["file"]) for s in snips] == [("function", "positive.go"), ("callee", "positive.go")]
    p = build_prompt(c, snips)
    assert '"category": "ignored-error"' in p and c.suspicion in p and "untrusted_repository_content" in p
    assert "   23 | \tsave(path)" in p and '    9 | \t\treturn errors.New("empty path")' in p


def test_review_likely_bug_with_visible_lines():
    c = by_function("ignored_error")["Persist"]
    run, seen = _runner({"verdict": "LIKELY_BUG", "justification": "error lost",
                         "lines": [{"file": "positive.go", "line": 23}], "behavior_hypothesis": "empty path",
                         "reproduction_condition": "call Persist(\"\")", "injection_suspected": False})
    rec = review_candidate(FIX / "ignored_error", c, runner=run)
    assert seen["schema"] is OUTPUT_SCHEMA and set(OUTPUT_SCHEMA["properties"]["verdict"]["enum"]) == \
        {"LIKELY_BUG", "NEEDS_REVIEW", "FALSE_POSITIVE"}
    assert rec["status"] == bm.LIKELY_BUG == c.status and rec["review"]["reproduction_condition"]


@pytest.mark.parametrize("answer,expected", [
    ({"verdict": "LIKELY_BUG", "lines": [{"file": "positive.go", "line": 999}]}, bm.NEEDS_REVIEW),  # invented line
    ({"verdict": "LIKELY_BUG", "lines": [{"file": "other.go", "line": 23}]}, bm.NEEDS_REVIEW),      # other file
    ({"verdict": "LIKELY_BUG", "lines": [{"file": "positive.go", "line": 23}],
      "injection_suspected": True}, bm.NEEDS_REVIEW),
    ({"verdict": "CONFIRMED", "lines": [{"file": "positive.go", "line": 23}]}, bm.NEEDS_REVIEW),    # bad enum
    ({"verdict": "FALSE_POSITIVE", "lines": []}, bm.NEEDS_REVIEW),                                  # can't dismiss
])
def test_review_cannot_invent_proof(answer, expected):
    c = by_function("ignored_error")["Persist"]
    rec = review_candidate(FIX / "ignored_error", c, runner=_runner(answer)[0])
    assert rec["status"] == expected


def test_review_cannot_override_detector_facts():
    got = by_function("ignored_error")
    likely = {"verdict": "LIKELY_BUG", "lines": [{"file": "negative.go", "line": 24}]}
    assert review_candidate(FIX / "ignored_error", got["Touch"], runner=_runner(likely)[0])["status"] == \
        bm.FALSE_POSITIVE
    likely["lines"] = [{"file": "ambiguous.go", "line": 5}]
    assert review_candidate(FIX / "ignored_error", got["PersistBestEffort"], runner=_runner(likely)[0])["status"] \
        == bm.NEEDS_REVIEW


def test_bugs_package_never_executes_or_publishes():
    root = Path(__file__).parents[1] / "src" / "github_security" / "bugs"
    for f in root.glob("*.py"):
        tree = ast.parse(f.read_text())
        mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        mods |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not mods & {"subprocess", "socket", "urllib", "http", "requests"}, f.name
        assert "github" not in {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}


# --------------------------------------------------------------------------- unchecked-split-index

def test_split_index_positive():
    got = by_function("split_index")
    for fn, line in (("ParseKV", 11), ("Port", 20), ("Command", 25), ("Minor", 30), ("ConfigPairs", 41)):
        c = got[fn]
        assert (c.file, c.line, c.category, c.status) == ("positive.go", line, "unchecked-split-index",
                                                           bm.BUG_CANDIDATE), fn
    assert "parts[1]" in got["ParseKV"].suspicion and "strings.SplitN" in got["ParseKV"].suspicion
    assert "len(parts) == 0" in got["Port"].suspicion                       # insufficient guard is named
    assert "strings.Fields" in got["Command"].suspicion


def test_split_index_negative():
    got = by_function("split_index")
    assert not {"ParseKVChecked", "Inside", "EarlyOr", "Switch", "Head", "Cut", "Args"} & set(got)
    c = got["Constant"]
    assert c.status == bm.FALSE_POSITIVE and c.negative_evidence == \
        ['constant input "a:b:c" splits into 3 element(s): index 2 exists']


def test_split_index_ambiguous_needs_review():
    got = by_function("split_index")
    # an early exit on !strings.Contains(s, "=") now PROVES SplitN(s, "=", 2)[1] (motif B): no longer reported;
    # an unmodelled validator keeps NEEDS_REVIEW (see split_guards/b_separator.go B12)
    assert "Validated" not in got
    assert got["Bounded"].status == bm.NEEDS_REVIEW and "non-constant" in got["Bounded"].ambiguity[0]
    assert got["Redefined"].status == bm.NEEDS_REVIEW and "redefined" in got["Redefined"].ambiguity[0]
    assert got["SplitKV"].status == bm.NEEDS_REVIEW and "separator" in got["SplitKV"].ambiguity[0]


def test_split_index_exact_set_and_reproduction_plan():
    cands = detect_go_bugs(FIX / "split_index")
    assert sorted((c.file, c.line) for c in cands) == \
        [("ambiguous.go", 20), ("ambiguous.go", 29), ("ambiguous.go", 35),
         ("negative.go", 50), ("positive.go", 11), ("positive.go", 20), ("positive.go", 25), ("positive.go", 30),
         ("positive.go", 41)]
    from github_security.bugs.reproduction import plan_reproduction
    t = plan_reproduction(by_function("split_index")["ParseKV"])
    assert t.executable is False and "panic" in t.observed_behavior_expected and "separator" in t.trigger


def test_split_index_does_not_change_other_categories():
    for case in ("ignored_error", "overwritten_error"):
        assert all(c.category != "unchecked-split-index" for c in detect_go_bugs(FIX / case))
    assert all(c.category == "unchecked-split-index" for c in detect_go_bugs(FIX / "split_index"))
