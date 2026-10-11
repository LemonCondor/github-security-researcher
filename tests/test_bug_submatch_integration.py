"""Orchestrator integration of unchecked-submatch-index: reproduction plan and review key identifiers."""
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.go_detectors import detect_go_bugs
from github_security.bugs.reproduction import plan_reproduction
from github_security.bugs.review import _key_identifiers

FIX = Path(__file__).parent / "fixtures" / "bugs" / "submatch_index"


def test_submatch_candidates_get_reproduction_task_and_key_identifiers():
    cands = [c for c in detect_go_bugs(FIX) if c.category == "unchecked-submatch-index"
             and c.status == "BUG_CANDIDATE"]
    assert cands
    for c in cands:
        t = plan_reproduction(c)
        assert t is not None and t.executable is False and "nil" in t.observed_behavior_expected
        src = (FIX / c.file).read_text().splitlines()
        assert _key_identifiers(c, src)
