"""unchecked-split-index guard modelling (short-circuit, separator presence, tagless switch, strings.Index).

Every split-result access in tests/fixtures/bugs/split_guards is annotated on its line:
  // SAFE              -> must NOT be reported (protection proven)
  // WANT: <STATUS>    -> must be reported with exactly that status
Unannotated lines must not be reported either. Fixtures mirror real cases (kompose 59af0f0, gonids 1c7af7b,
go-github 4dbe048, git-sync cf98d83) and are parsed only.
"""
import re
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.go_detectors import detect_go_bugs

FIX = Path(__file__).parent / "fixtures" / "bugs" / "split_guards"


def annotations():
    want, safe = {}, set()
    for f in sorted(FIX.glob("*.go")):
        for i, line in enumerate(f.read_text().splitlines(), 1):
            m = re.search(r"// WANT: (\w+)", line)
            if m:
                want[(f.name, i)] = m.group(1)
            elif "// SAFE" in line:
                safe.add((f.name, i))
    return want, safe


@pytest.fixture(scope="module")
def found():
    return {(c.file, c.line): c for c in detect_go_bugs(FIX) if c.category == "unchecked-split-index"}


@pytest.mark.parametrize("motif", ["a_shortcircuit.go", "b_separator.go", "c_switch.go", "d_index.go", "e_mixed.go",
                                   "f_alias.go"])
def test_annotated_lines(found, motif):
    want, safe = annotations()
    got = {k: v.status for k, v in found.items() if k[0] == motif}
    exp = {k: v for k, v in want.items() if k[0] == motif}
    assert got == exp, f"\nexpected {sorted(exp.items())}\n     got {sorted(got.items())}"
    assert not {k for k in safe if k[0] == motif} & set(got)


def test_each_motif_has_safe_unprotected_and_tricky_cases():
    want, safe = annotations()
    for motif in ("a_shortcircuit.go", "b_separator.go", "c_switch.go", "d_index.go", "f_alias.go"):
        assert sum(1 for k in safe if k[0] == motif) >= 2
        assert sum(1 for k in want if k[0] == motif) >= 2


def test_git_sync_pr1006_shape_still_reported(found):
    c = found[("e_mixed.go", next(k[1] for k in annotations()[0] if k[0] == "e_mixed.go" and
                                  "parts[1]" in (FIX / "e_mixed.go").read_text().splitlines()[k[1] - 1]))]
    assert c.status == "BUG_CANDIDATE" and "parts[1]" in c.suspicion and c.function == "E4"


def test_proven_protection_is_named_in_no_candidate_and_never_confirmed(found):
    assert all(c.status in ("BUG_CANDIDATE", "NEEDS_REVIEW", "FALSE_POSITIVE") for c in found.values())
