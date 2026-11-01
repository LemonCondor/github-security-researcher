"""D6 retrospective benchmark: does the D1-D5 pipeline reproduce the historical decisions?

Uses ONLY facts already verified in earlier reviews (no new scan, no new investigation, nothing invented).
Each case constructs the D1-D4 model objects from those recorded facts and the real source change (when one was
observed), runs the deterministic D5 engine, and compares its verdict to the historical decision.

A delta is never turned into a confirmed vulnerability here; we only check the triage VERDICT (BLOCKED /
UNCERTAIN / PRIORITIZED / NO_FUNCTIONAL_DELTA).
"""
from github_security.deploy.delta import build_candidate
from github_security.deploy.models import (AuditCoverage, DIRECT, EXACT_MATCH, MAPPED, MappingResult,
                                            NO_GIT_MATCH, PROXY_EIP1967, ProxyRelationship, RESOLVED, Source,
                                            TC_BLOCKED, TC_PRIORITIZED, TC_UNCERTAIN, UNKNOWN, VERIFIED,
                                            VersionMatch)

TS = "2026-10-31T00:00:00.000+00:00"


def _mapping(status=MAPPED, kind=DIRECT, resolution=RESOLVED):
    proxy = ProxyRelationship("EIP1967", resolution, "0x" + "bb" * 20, resolution == RESOLVED, None, None,
                              VERIFIED) if kind == PROXY_EIP1967 else None
    return MappingResult(chain_id=1, address="0x" + "aa" * 20, status=status, kind=kind, certainty=VERIFIED,
                         proxy=proxy)


class _V:
    certainty = VERIFIED


def _vm(status=EXACT_MATCH, ref="owner/repo@vX"):
    return VersionMatch(1, "0x" + "aa" * 20, status, VERIFIED, ref, 1, 1, True, sources=[Source("m", "s", TS)])


def _cov(status, doc_state):
    return AuditCoverage(1, "0x" + "aa" * 20, "owner/repo@vX", status, doc_state, ["tag:v1"], certainty=VERIFIED)


def _wrap(fn):
    return f"// SPDX\npragma solidity ^0.8.20;\ncontract C {{\n{fn}\n}}\n"


# =================================================================== Spark
# Facts (TARGET_SELECTION_REPORT): deployed MainnetController source keccak-IDENTICAL to audited tag v1.10.0;
# coverage EXPLICIT_DELTA, reviewed. Historical decision: REJECT (deployed == audited).
def test_spark_reproduced_blocked():
    # identical source => no functional delta; and coverage says the deployed version is the audited one.
    same = _wrap("function f() external onlyGov { x = 1; }\nuint256 x;")
    tc = build_candidate(1, "0x" + "aa" * 20, "src/MainnetController.sol", same, same,
                         mapping=_mapping(kind=PROXY_EIP1967), verified=_V(), version_match=_vm(ref="repo@v1.10.0"),
                         coverage=_cov("EXPLICIT_DELTA", "REVIEWED"), observed_at=TS)
    # No functional delta at all (deployed source == audited source).
    assert tc.status == "NO_FUNCTIONAL_DELTA"


# =================================================================== Sky Diamond PAU
# Facts (SKY_DEPLOYMENT_VERIFICATION): the post-audit facts (#235/#236) are NOT in the deployed facet set.
# At the triage level: the changed code is not deployed => the mapped target for that code is NOT_DEPLOYED.
# Historical decision: REJECT.
def test_sky_reproduced_blocked_not_deployed():
    a = _wrap("function swap(uint256 a) external onlyRelayer { t.transfer(msg.sender, a); }\nI t;")
    b = _wrap("function swap(uint256 a) external { t.transfer(msg.sender, a); }\nI t;")   # the dev-branch change
    tc = build_candidate(1, "0x" + "aa" * 20, "src/facets/SwapAssetFacet.sol", a, b,
                         mapping=_mapping(status="NOT_DEPLOYED", kind=None), verified=_V(),
                         version_match=_vm(), coverage=_cov("UNKNOWN", "UNKNOWN"), observed_at=TS)
    assert tc.status == TC_BLOCKED and any("NOT_DEPLOYED" in r or "status" in r for r in tc.stop_reasons)


# =================================================================== Origin Compounding Staking
# Facts (ORIGIN_COMPOUNDING_STAKING_REVIEW): snapBalances/verifyBalances went external onlyRegistrator -> external
# (permissionless), deployed and source-verified, POST the last public audit; public coverage UNKNOWN (a private
# audit may exist). Historical decision: READY_FOR_INVESTIGATION but verify private coverage first (== UNCERTAIN).
def test_origin_reproduced_uncertain_pending_coverage():
    a = _wrap("function snapBalances() external onlyRegistrator { snapped = block.timestamp; }\nuint256 snapped;")
    b = _wrap("function snapBalances() external { snapped = block.timestamp; }\nuint256 snapped;")
    tc = build_candidate(1, "0x" + "aa" * 20, "CompoundingStakingStrategy.sol", a, b,
                         mapping=_mapping(kind=PROXY_EIP1967), verified=_V(),
                         version_match=_vm(status=EXACT_MATCH, ref="origin-dollar@deployed"),
                         coverage=_cov("UNKNOWN", "UNKNOWN"), observed_at=TS)
    # Permissionless change detected, deployed+verified, but coverage UNKNOWN => UNCERTAIN, never auto-prioritized.
    from github_security.deploy.models import FUNCTION_PERMISSIONLESS
    assert FUNCTION_PERMISSIONLESS in tc.categories
    assert tc.status == TC_UNCERTAIN and tc.status != TC_PRIORITIZED


# =================================================================== Alchemix V3
# Facts (EDGE_REPORT / PISTE verdicts): the post-audit redeem() change was a hardcoded tolerance constant
# (5_256_001) + a reverted rounding fix; historical decision REJECT because the effect is DUST / non-amplifiable
# (an ECONOMIC-significance judgement). Also deployment of the reworked redeem() was never verified.
# Expectation: the engine detects the delta category but CANNOT reproduce the "reject as dust" decision --
# this is a documented LIMIT of D5 (it triages location, not economic magnitude).
def test_alchemix_delta_detected_but_economic_judgement_not_reproduced():
    a = _wrap("function redeem(uint256 amt) external { require(amt <= liveEarmarked); d = amt; }\nuint256 d; uint256 liveEarmarked;")
    b = _wrap("function redeem(uint256 amt) external { uint256 r = liveEarmarked - amt; "
              "uint256 w = (r <= 5256001) ? 0 : r; d = w; }\nuint256 d; uint256 liveEarmarked;")
    tc = build_candidate(1, "0x" + "aa" * 20, "src/AlchemistV3.sol", a, b,
                         mapping=_mapping(kind=PROXY_EIP1967), verified=_V(), version_match=_vm(),
                         coverage=_cov("UNKNOWN", "UNKNOWN"), observed_at=TS)
    # A tolerance/accounting delta IS flagged (the engine does its job: locate the change)...
    from github_security.deploy.models import (ACCOUNTING_OR_ASSET_CONVERSION_CHANGED,
                                               TOLERANCE_OR_THRESHOLD_CHANGED)
    assert tc.categories and (set(tc.categories) & {TOLERANCE_OR_THRESHOLD_CHANGED,
                                                    ACCOUNTING_OR_ASSET_CONVERSION_CHANGED})
    # ...but the engine does NOT (and must not) conclude "dust => reject": it can only reach UNCERTAIN here
    # (coverage UNKNOWN). The economic magnitude that drove our historical REJECT is out of D5's scope.
    assert tc.status in (TC_UNCERTAIN,) and tc.status != TC_BLOCKED
