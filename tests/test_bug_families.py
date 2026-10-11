"""Bug-family signals learned from confirmed upstream bugs (F1 late length guard, F3 ignored acquire + deferred
release, F4 nil checked before err). Signals raise the ranking prior; they never change the status rules."""
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs.go_detectors import FAMILY_CONFIDENCE, detect_go_bugs
from github_security.bugs.reproduction import plan_reproduction

FIX = Path(__file__).parent / "fixtures" / "bugs" / "families"


@pytest.fixture(scope="module")
def found():
    return {(c.function, c.category): c for c in detect_go_bugs(FIX)}


def test_f1_late_length_guard_is_ranked_high(found):
    c = found[("LateGuard", "unchecked-split-index")]
    assert c.confidence == FAMILY_CONFIDENCE and "late-length-guard" in c.suspicion and c.status == "BUG_CANDIDATE"
    plain = found[("NoLateGuard", "unchecked-split-index")]
    assert plain.confidence < FAMILY_CONFIDENCE and "late-length-guard" not in plain.suspicion
    assert ("EarlyGuard", "unchecked-split-index") not in found


def test_f3_ignored_acquire_then_deferred_release(found):
    c = found[("ctr.UpdateBad", "ignored-error")]
    assert c.confidence == FAMILY_CONFIDENCE and "deferred-release" in c.suspicion
    assert ("ctr.UpdateGood", "ignored-error") not in found


def test_f4_nil_checked_before_err(found):
    c = found[("SumBad", "nil-before-err-check")]
    assert c.status == "BUG_CANDIDATE" and c.confidence == FAMILY_CONFIDENCE
    assert "v == nil" in c.suspicion and "err" in c.suspicion
    assert not [k for k in found if k[1] == "nil-before-err-check" and k[0] != "SumBad"]
    task = plan_reproduction(c)
    assert task is not None and task.executable is False


def test_f6_split_index_into_parse_with_discarded_error(found):
    c = found[("LastNumberBad", "unchecked-split-index")]
    assert c.confidence == FAMILY_CONFIDENCE and "discarded-parse-error" in c.suspicion
    assert ("LastNumberChecked", "unchecked-split-index") not in found
