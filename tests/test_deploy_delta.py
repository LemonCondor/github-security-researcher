"""D5 delta engine: deterministic, offline, no LLM. Fixtures are tiny Solidity source pairs.

Each case asserts explicit expectations (category set, funds proximity, candidate status). STOP conditions
must prevail over the score; an uncertain delta must never be labelled PRIORITIZED.
"""
import json

import pytest

from github_security.deploy.delta import build_candidate, diff_sources
from github_security.deploy.models import (ACCOUNTING_OR_ASSET_CONVERSION_CHANGED, AuditCoverage,
                                            DIRECT_USER_FUNDS_PATH, FUNCTION_PERMISSIONLESS, FUNDS_UNKNOWN,
                                            MappingResult, NO_IDENTIFIED_FUNDS_PATH, PERMISSION_RELAXATION,
                                            PROXY_EIP1967, ProxyRelationship, Source, TC_BLOCKED,
                                            TC_NO_FUNCTIONAL_DELTA, TC_PRIORITIZED, TC_UNCERTAIN,
                                            TOLERANCE_OR_THRESHOLD_CHANGED, VALIDATION_REMOVED_OR_WEAKENED,
                                            VERIFIED, VersionMatch, RESOLVED, MAPPED, DIRECT, EXACT_MATCH)
from github_security.deploy.store import DeployStore
from github_security.storage.database import Database

ADDR = "0x" + "11" * 20
TS = "2026-10-31T00:00:00.000+00:00"


def wrap(body_fns: str, name="C") -> str:
    return f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract {name} {{\n{body_fns}\n}}\n"


def cats(deltas, sig=None):
    out = set()
    for d in deltas:
        if sig is None or d.function == sig:
            out.update(d.categories)
    return out


# ---- full evidence chain helpers (so gating is satisfied unless a test overrides it) ----
def ok_mapping():
    return MappingResult(chain_id=1, address=ADDR, status=MAPPED, kind=PROXY_EIP1967, certainty=VERIFIED,
                         proxy=ProxyRelationship("EIP1967", RESOLVED, "0x" + "bb" * 20, True, None, None, VERIFIED))


def ok_verified():
    class V:  # minimal stand-in carrying certainty
        certainty = VERIFIED
    return V()


def ok_version():
    return VersionMatch(1, ADDR, EXACT_MATCH, VERIFIED, "owner/repo@v1.15.0", 2, 2, True,
                        sources=[Source("deploy_match", "s", TS)])


def cov(status="PRIOR_VERSION_ONLY", doc_state="REVIEWED"):
    return AuditCoverage(1, ADDR, "owner/repo@v1.15.0", status, doc_state, ["tag:v1.14.0"], certainty=VERIFIED)


def candidate(audited, deployed, **kw):
    base = dict(mapping=ok_mapping(), verified=ok_verified(), version_match=ok_version(), coverage=cov())
    base.update(kw)
    return build_candidate(1, ADDR, "src/C.sol", audited, deployed, observed_at=TS, **base)


# ============================================================ category detection
def test_permission_removed_fully_is_permissionless():
    a = wrap("function snap() external onlyOwner { x = 1; }\nuint256 x;")
    b = wrap("function snap() external { x = 1; }\nuint256 x;")
    assert cats(diff_sources(a, b), "snap()") == {FUNCTION_PERMISSIONLESS}


def test_one_of_two_gates_removed_is_relaxation():
    a = wrap("function f() external onlyOwner onlyGov { x = 1; }\nuint256 x;")
    b = wrap("function f() external onlyGov { x = 1; }\nuint256 x;")
    assert cats(diff_sources(a, b), "f()") == {PERMISSION_RELAXATION}


def test_function_made_public():
    a = wrap("function f() internal { x = 1; }\nuint256 x;")
    b = wrap("function f() public { x = 1; }\nuint256 x;")
    assert PERMISSION_RELAXATION in cats(diff_sources(a, b), "f()")


def test_validation_guard_removed():
    a = wrap("function f(uint256 a) external { require(a < 100, \"big\"); y = a; }\nuint256 y;")
    b = wrap("function f(uint256 a) external { y = a; }\nuint256 y;")
    c = cats(diff_sources(a, b), "f(a)")
    assert VALIDATION_REMOVED_OR_WEAKENED in c


def test_threshold_increased():
    a = wrap("function f(uint256 a) external { require(a <= 100); y = a; }\nuint256 y;")
    b = wrap("function f(uint256 a) external { require(a <= 5000000); y = a; }\nuint256 y;")
    assert TOLERANCE_OR_THRESHOLD_CHANGED in cats(diff_sources(a, b), "f(a)")


def test_accounting_formula_changed():
    a = wrap("function f() external { total = shares * rate / 1e18; }\nuint256 total; uint256 shares; uint256 rate;")
    b = wrap("function f() external { total = shares * rate / 1e9; }\nuint256 total; uint256 shares; uint256 rate;")
    assert cats(diff_sources(a, b), "f()") & {ACCOUNTING_OR_ASSET_CONVERSION_CHANGED, TOLERANCE_OR_THRESHOLD_CHANGED}


# ============================================================ non-functional diffs
def test_cosmetic_change_is_no_delta():
    a = wrap("function f() external { x = 1; }\nuint256 x;")
    b = wrap("function f() external {\n    x = 1;  // set x\n}\nuint256 x;")
    assert diff_sources(a, b) == []


def test_comment_only_change_is_no_delta_candidate():
    a = wrap("function f() external { x = 1; }\nuint256 x;")
    b = wrap("// new banner comment\nfunction f() external { x = 1; }\nuint256 x;")
    tc = candidate(a, b)
    assert tc.status == TC_NO_FUNCTIONAL_DELTA and not tc.deltas


def test_unused_internal_function_change_has_unknown_or_no_funds_path():
    a = wrap("function _helper(uint256 a) internal pure returns (uint256) { return a + 1; }")
    b = wrap("function _helper(uint256 a) internal pure returns (uint256) { return a + 2; }")
    deltas = diff_sources(a, b)
    assert deltas and deltas[0].funds == NO_IDENTIFIED_FUNDS_PATH   # pure: no funds path


# ============================================================ funds proximity
def test_direct_funds_path_when_transfer_in_changed_function():
    a = wrap("function w(uint256 a) external onlyOwner { token.transfer(msg.sender, a); }\nI token;")
    b = wrap("function w(uint256 a) external { token.transfer(msg.sender, a); }\nI token;")
    d = [x for x in diff_sources(a, b) if x.function == "w(a)"][0]
    assert d.funds == DIRECT_USER_FUNDS_PATH and FUNCTION_PERMISSIONLESS in d.categories


def test_state_change_without_transfer_is_funds_unknown():
    a = wrap("function f() external onlyOwner { x = 1; }\nuint256 x;")
    b = wrap("function f() external { x = 1; }\nuint256 x;")
    d = [x for x in diff_sources(a, b) if x.function == "f()"][0]
    assert d.funds == FUNDS_UNKNOWN            # changes state, no transfer here: not guessed


# ============================================================ evidence-chain gate / STOP
PERMLESS_A = wrap("function w(uint256 a) external onlyOwner { token.transfer(msg.sender, a); }\nI token;")
PERMLESS_B = wrap("function w(uint256 a) external { token.transfer(msg.sender, a); }\nI token;")


def test_full_chain_uncovered_delta_is_prioritized():
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=cov("PRIOR_VERSION_ONLY", "MENTIONED"))
    assert tc.status == TC_PRIORITIZED and FUNCTION_PERMISSIONLESS in tc.categories
    assert tc.funds_direct()  # helper below


def test_delta_already_covered_is_blocked_despite_high_priority():
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=cov("EXPLICIT_DELTA", "FIX_VERIFIED"))
    assert tc.status == TC_BLOCKED and any("already covered" in r for r in tc.stop_reasons) and tc.score == 0.0


def test_source_unverified_blocks():
    vm = VersionMatch(1, ADDR, "SOURCE_UNVERIFIED", VERIFIED, None, 0, 0, None, sources=[Source("m", "s", TS)])
    tc = candidate(PERMLESS_A, PERMLESS_B, version_match=vm)
    assert tc.status == TC_BLOCKED and any("match" in r for r in tc.stop_reasons)


def test_out_of_scope_blocks():
    mp = MappingResult(chain_id=1, address=ADDR, status="NOT_IN_SCOPE", kind=None, certainty=VERIFIED)
    tc = candidate(PERMLESS_A, PERMLESS_B, mapping=mp)
    assert tc.status == TC_BLOCKED


def test_unknown_implementation_blocks():
    mp = MappingResult(chain_id=1, address=ADDR, status=MAPPED, kind=PROXY_EIP1967, certainty=VERIFIED,
                       proxy=ProxyRelationship("EIP1967", "NOT_RESOLVED", "0x" + "bb" * 20, None, None, None, VERIFIED))
    tc = candidate(PERMLESS_A, PERMLESS_B, mapping=mp)
    assert tc.status == TC_BLOCKED and any("implementation" in r for r in tc.stop_reasons)


def test_no_funds_path_blocks_even_with_permission_change():
    a = wrap("function f() external onlyOwner view returns (uint256) { return x; }\nuint256 x;")
    b = wrap("function f() external view returns (uint256) { return x; }\nuint256 x;")
    tc = candidate(a, b)
    assert tc.status == TC_BLOCKED and any("funds path" in r for r in tc.stop_reasons)


def test_coverage_unknown_is_uncertain_not_prioritized():
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=cov("UNKNOWN", "UNKNOWN"))
    assert tc.status == TC_UNCERTAIN       # coverage not known: never promoted, whatever the score


def test_incomplete_chain_is_uncertain_never_prioritized():
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=None)
    assert tc.status == TC_UNCERTAIN and tc.score >= 0


def test_score_never_promotes_blocked():
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=cov("EXPLICIT_DELTA", "REVIEWED"))
    assert tc.status == TC_BLOCKED and tc.score == 0.0


# ============================================================ store
def test_store_roundtrip(tmp_path):
    db = Database(tmp_path / "gsr.db")
    store = DeployStore(db)
    tc = candidate(PERMLESS_A, PERMLESS_B, coverage=cov("PRIOR_VERSION_ONLY", "MENTIONED"))
    store.record_triage_candidate(tc)
    rows = store.triage_candidates(status=TC_PRIORITIZED)
    assert len(rows) == 1 and json.loads(rows[0]["categories"]) and rows[0]["funds"] == DIRECT_USER_FUNDS_PATH
    with pytest.raises(Exception):
        db.conn.execute("INSERT INTO deploy_triage_candidates(chain_id,address,file,status,certainty,observed_at)"
                        " VALUES (1,'a','f','BOGUS','VERIFIED','t')")


# small helper attached for readability in one test
def _funds_direct(self):
    return any(d.funds == DIRECT_USER_FUNDS_PATH for d in self.deltas)


from github_security.deploy.models import TriageCandidate   # noqa: E402
TriageCandidate.funds_direct = _funds_direct
