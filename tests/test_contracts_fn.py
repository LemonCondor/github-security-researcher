"""contracts.solidity/2 — regressions for the 4 false negatives found by validation corpus v1 (V3, A2, V2, D3).
Each case has a development fixture with positives AND safe look-alikes (tests/fixtures/contracts/)."""
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_solidity")

from github_security.contracts import run                       # noqa: E402
from github_security.contracts.engine import ENGINE              # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "contracts"


def hits(name, rule, include_suppressed=False):
    return {(f["location"]["contract"], f["location"]["function"]): f
            for f in run(FIX / name, include_suppressed=include_suppressed)["findings"] if f["rule"] == rule}


def test_engine_version_bumped():
    assert ENGINE == "contracts.solidity/2"


def test_fallback_receive_writing_authority_state():                      # v1 V3
    h = hits("fallback_access_pos.sol", "SOL-ACCESS-CONTROL")
    assert set(h) == {("FallbackTakeover", "fallback"), ("ReceiveAdmin", "receive"), ("FallbackKill", "fallback")}
    assert all(f["status"] == "CANDIDATE" for f in h.values())
    assert hits("fallback_access_neg.sol", "SOL-ACCESS-CONTROL") == {}
    sup = hits("fallback_access_neg.sol", "SOL-ACCESS-CONTROL", include_suppressed=True)
    assert set(sup) == {("GuardedFallback", "fallback")} and sup[("GuardedFallback", "fallback")]["status"] == "FALSE_POSITIVE"


def test_misnamed_legacy_constructor():                                   # v1 A2
    h = hits("legacy_ctor_pos.sol", "SOL-ACCESS-CONTROL")
    assert set(h) == {("Pyramid", "DynamicPyramid"), ("Wallet", "Walet")}
    assert all(f["status"] == "CANDIDATE" and "SWC-118" in f["description"] for f in h.values())
    # correctly named legacy constructor is a constructor, not an entry point; `!=` anti-repeat is not authority
    assert hits("legacy_ctor_neg.sol", "SOL-ACCESS-CONTROL", include_suppressed=True).keys() <= {
        ("Rubix2", "changeCreator")}


def test_unprotected_setter_of_role_derived_from_use():                   # v1 D3
    h = hits("authority_var_pos.sol", "SOL-ACCESS-CONTROL")
    assert set(h) == {("LibConsumer", "setLib"), ("Fund", "setManager")}
    assert "delegatecall target" in h[("LibConsumer", "setLib")]["description"]
    assert "compared with msg.sender" in h[("Fund", "setManager")]["description"]
    assert hits("authority_var_neg.sol", "SOL-ACCESS-CONTROL") == {}


def test_inline_assembly_call_result_ignored():                           # v1 V2
    h = hits("asm_call_pos.sol", "SOL-UNCHECKED-CALL")
    assert {k: f["status"] for k, f in h.items()} == {
        ("AsmSender", "rawPay"): "CANDIDATE", ("AsmSender", "rawPayAssign"): "CANDIDATE",
        ("AsmSender", "rawPayPop"): "NEEDS_REVIEW"}
    assert hits("asm_call_neg.sol", "SOL-UNCHECKED-CALL") == {}
    sup = hits("asm_call_neg.sol", "SOL-UNCHECKED-CALL", include_suppressed=True)
    assert {k[1] for k in sup} == {"a", "b", "c", "d", "e"}
    assert all(e["strength"] == "strong" for f in sup.values() for e in f["evidence"] if e["kind"] == "negative")
