"""D7 — conservative static intra-file call graph for indirect funds-path detection.

No LLM, no name inference, no speculative resolution. A function is classified INDIRECT only when an
UNAMBIGUOUS, resolved intra-file call chain (depth <= 3, cycles broken) reaches a recognised financial sink
(a value transfer). External calls, interfaces, builtins and ambiguous dispatch are not followed (UNKNOWN).
Transfers, accounting changes, state changes and balance reads are kept distinct.
"""
from github_security.deploy.delta import build_candidate, diff_sources
from github_security.deploy.models import (AuditCoverage, DIRECT, DIRECT_USER_FUNDS_PATH, EXACT_MATCH,
                                            FUNCTION_PERMISSIONLESS, FUNDS_UNKNOWN, INDIRECT_USER_FUNDS_PATH,
                                            MAPPED, MappingResult, NO_IDENTIFIED_FUNDS_PATH, PROXY_EIP1967,
                                            ProxyRelationship, RESOLVED, Source, TC_PRIORITIZED, VERIFIED,
                                            VersionMatch)
from github_security.deploy.solfn import function_facts, funds_proximity, parse_source

ADDR = "0x" + "11" * 20
TS = "2026-11-01T00:00:00.000+00:00"


def fp(src: str, sig: str) -> str:
    return funds_proximity(sig, function_facts(parse_source(src)))


def wrap(body: str) -> str:
    return f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract C {{\n{body}\n}}\n"


# 1. modified function -> direct transfer
def test_direct_transfer():
    src = wrap("function f() external { t.transfer(msg.sender, 1); }\nI t;")
    assert fp(src, "f()") == DIRECT_USER_FUNDS_PATH


# 2. modified function -> helper -> transfer
def test_one_helper_to_transfer():
    src = wrap("function f() external { h(); }\n"
               "function h() internal { t.transfer(msg.sender, 1); }\nI t;")
    assert fp(src, "f()") == INDIRECT_USER_FUNDS_PATH


# 3. modified function -> two helpers -> transfer
def test_two_helpers_to_transfer():
    src = wrap("function f() external { h1(); }\n"
               "function h1() internal { h2(); }\n"
               "function h2() internal { t.transfer(msg.sender, 1); }\nI t;")
    assert fp(src, "f()") == INDIRECT_USER_FUNDS_PATH


# 4. unresolved external call
def test_external_call_unresolved_is_unknown():
    src = wrap("function f() external { bank.pay(1); }\nB bank;")
    assert fp(src, "f()") == FUNDS_UNKNOWN


# 5. ambiguous dispatch (overloaded name) -> not followed even though both overloads transfer
def test_ambiguous_dispatch_is_unknown():
    src = wrap("function f() external { pay(1); }\n"
               "function pay(uint256 a) internal { t.transfer(msg.sender, a); }\n"
               "function pay(address x) internal { t.transfer(x, 1); }\nI t;")
    assert fp(src, "f()") == FUNDS_UNKNOWN


# 6. interface call -> UNKNOWN (external dispatch, not followed)
def test_interface_call_is_unknown():
    src = wrap("function f() external { IVault(v).withdraw(); }\naddress v;")
    assert fp(src, "f()") == FUNDS_UNKNOWN


# 7. cycle -> terminates, no sink reached
def test_cycle_terminates_unknown():
    src = wrap("function a() external { b(); }\n"
               "function b() internal { a(); }")
    assert fp(src, "a()") == FUNDS_UNKNOWN


# 8. depth beyond the limit of 3 -> sink not attributed
def test_depth_over_limit_not_attributed():
    src = wrap("function f() external { h1(); }\n"
               "function h1() internal { h2(); }\n"
               "function h2() internal { h3(); }\n"
               "function h3() internal { h4(); }\n"
               "function h4() internal { t.transfer(msg.sender, 1); }\nI t;")
    assert fp(src, "f()") == FUNDS_UNKNOWN


# 9. modified function with no financial path (pure) -> NO path
def test_no_financial_path_pure():
    src = wrap("function f(uint256 a) external pure returns (uint256) { return a + 1; }")
    assert fp(src, "f(a)") == NO_IDENTIFIED_FUNDS_PATH


# 10. a helper containing a sink exists but is never called from the modified function
def test_unreachable_sink_not_attributed():
    src = wrap("function f() external { x = 1; }\nuint256 x;\n"
               "function p() internal { t.transfer(msg.sender, 1); }\nI t;")
    assert fp(src, "f()") == FUNDS_UNKNOWN   # sink exists but is unreachable from f()


# 11. balance read without transfer -> NO path (a read is not a sink)
def test_balance_read_is_no_path():
    src = wrap("function f() external view returns (uint256) { return t.balanceOf(address(this)); }\nI t;")
    assert fp(src, "f()") == NO_IDENTIFIED_FUNDS_PATH


# 12. accounting modification without transfer -> UNKNOWN, distinct from a read and from NO path
def test_accounting_without_transfer_is_unknown():
    src = wrap("function f() external { total = shares * rate / 1e18; }\n"
               "uint256 total; uint256 shares; uint256 rate;")
    assert fp(src, "f()") == FUNDS_UNKNOWN


# ----- the indirect path is a real funds path: it propagates through the delta engine and ranking -----
def _mapping():
    return MappingResult(chain_id=1, address=ADDR, status=MAPPED, kind=PROXY_EIP1967, certainty=VERIFIED,
                         proxy=ProxyRelationship("EIP1967", RESOLVED, "0x" + "bb" * 20, True, None, None, VERIFIED))


class _V:
    certainty = VERIFIED


def test_indirect_path_detected_through_diff_sources():
    a = wrap("function f() external onlyOwner { h(); }\nfunction h() internal { t.transfer(msg.sender, 1); }\nI t;")
    b = wrap("function f() external { h(); }\nfunction h() internal { t.transfer(msg.sender, 1); }\nI t;")
    d = [x for x in diff_sources(a, b) if x.function == "f()"][0]
    assert d.funds == INDIRECT_USER_FUNDS_PATH and FUNCTION_PERMISSIONLESS in d.categories


def test_indirect_path_can_be_prioritized_not_blocked():
    a = wrap("function f() external onlyOwner { h(); }\nfunction h() internal { t.transfer(msg.sender, 1); }\nI t;")
    b = wrap("function f() external { h(); }\nfunction h() internal { t.transfer(msg.sender, 1); }\nI t;")
    vm = VersionMatch(1, ADDR, EXACT_MATCH, VERIFIED, "owner/repo@v1", 2, 2, True, sources=[Source("m", "s", TS)])
    cov = AuditCoverage(1, ADDR, "owner/repo@v1", "PRIOR_VERSION_ONLY", "MENTIONED", ["tag:v0"], certainty=VERIFIED)
    tc = build_candidate(1, ADDR, "src/C.sol", a, b, mapping=_mapping(), verified=_V(),
                         version_match=vm, coverage=cov, observed_at=TS)
    assert tc.status == TC_PRIORITIZED and not tc.stop_reasons
