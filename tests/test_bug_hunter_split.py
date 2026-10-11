"""unchecked-split-index: false-negative risks of the guard modelling (tests/fixtures/bugs/split_fn_risks).

Same annotation scheme as tests/test_split_guards.py: `// SAFE` = no candidate, `// WANT: <STATUS>` = exactly
that status; unannotated lines must not be reported. Parsed only, never compiled.
"""
import re
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.go_detectors import detect_go_bugs, detect_go_report

FIX = Path(__file__).parent / "fixtures" / "bugs" / "split_fn_risks"


def annotations(name):
    want, safe = {}, set()
    for i, line in enumerate((FIX / name).read_text().splitlines(), 1):
        m = re.search(r"// WANT: (\w+)", line)
        if m:
            want[i] = m.group(1)
        elif "// SAFE" in line:
            safe.add(i)
    return want, safe


@pytest.fixture(scope="module")
def found():
    return {(c.file, c.line): c for c in detect_go_bugs(FIX) if c.category == "unchecked-split-index"}


def test_fn_risks_annotated(found):
    want, safe = annotations("f_risks.go")
    got = {k[1]: v.status for k, v in found.items() if k[0] == "f_risks.go"}
    assert got == want, f"\nexpected {sorted(want.items())}\n     got {sorted(got.items())}"
    assert not safe & set(got)


def test_loop_and_closure_carried_values_are_explained(found):
    want, _ = annotations("f_risks.go")
    amb = {ln: " ".join(found[("f_risks.go", ln)].ambiguity) for ln, s in want.items() if s == "NEEDS_REVIEW"}
    assert amb and all("later" in a for a in amb.values()), amb


def test_safe_sites_leave_a_proof():
    rep = detect_go_report(FIX)
    _, safe = annotations("f_risks.go")
    proven = {c.line for c, p in rep.suppressed if c.file == "f_risks.go" and p["kind"] == "guard_recognized"}
    assert safe <= proven


SUB = Path(__file__).parent / "fixtures" / "bugs" / "submatch_index"


def test_submatch_index_annotated():
    want, safe = {}, set()
    for i, line in enumerate((SUB / "g_submatch.go").read_text().splitlines(), 1):
        m = re.search(r"// WANT: (\w+)", line)
        if m:
            want[i] = m.group(1)
        elif "// SAFE" in line:
            safe.add(i)
    rep = detect_go_report(SUB)
    got = {c.line: c.status for c in rep.candidates if c.category == "unchecked-submatch-index"}
    assert got == want, f"\nexpected {sorted(want.items())}\n     got {sorted(got.items())}"
    assert safe <= {c.line for c, p in rep.suppressed if c.category == "unchecked-submatch-index"}
    assert not [c for c in rep.candidates if c.category != "unchecked-submatch-index"]


def test_submatch_group_overflow_is_explained():
    c = next(c for c in detect_go_bugs(SUB) if c.function == "G5")
    assert "only 2 group(s)" in c.suspicion and c.status == "BUG_CANDIDATE"


def test_submatch_detector_silent_on_split_fixtures():
    root = Path(__file__).parent / "fixtures" / "bugs"
    for sub in ("split_index", "split_guards", "split_fn_risks", "ignored_error", "overwritten_error"):
        assert not [c for c in detect_go_bugs(root / sub) if c.category == "unchecked-submatch-index"], sub
