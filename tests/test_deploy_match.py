"""D3: verified-source <-> git version matching. Deterministic, offline.

A fake Sourcify transport returns recorded JSON; git refs are supplied as {path: bytes} blobs. No network,
no real protocol. keccak256 of a source's bytes is what solc records in metadata.sources[*].keccak256.
"""
import json

import pytest

from github_security.deploy.keccak import keccak256_hex
from github_security.deploy.gitmatch import classify, match_sources
from github_security.deploy.models import (COMPILER_MATCH, CONFLICTING, EXACT_MATCH, NO_GIT_MATCH, PARTIAL_MATCH,
                                           SOURCE_UNVERIFIED, UNKNOWN, VERIFIED)
from github_security.deploy.store import DeployStore
from github_security.deploy.verify import fetch_sourcify, is_verified, parse_sourcify
from github_security.deploy.models import Source
from github_security.storage.database import Database

VAULT = b"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract Vault { uint256 x; }\n"
LIB = b"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nlibrary MathLib { }\n"
VAULT_V2 = VAULT + b"// one line added\n"
K_VAULT, K_LIB = keccak256_hex(VAULT), keccak256_hex(LIB)


def sourcify_payload(*, runtime="exact_match", reasons=None, immutable=False, libs=None,
                     sources=("src/Vault.sol", "src/MathLib.sol"), with_keccak=True, metadata=True):
    keccaks = {"src/Vault.sol": {"keccak256": K_VAULT}, "src/MathLib.sol": {"keccak256": K_LIB}}
    transformations = [{"reason": r} for r in (reasons or [])]
    rt = {"onchainBytecode": "0xdead", "recompiledBytecode": "0xdead",
          "transformations": transformations, "transformationValues": {"libraries": libs or {}}}
    if immutable:
        rt["immutableReferences"] = {"1050": [{"start": 10, "length": 32}]}
    body = {
        "match": runtime, "runtimeMatch": runtime, "creationMatch": runtime, "verifiedAt": "2026-09-01T00:00:00Z",
        "compilation": {"compiler": "solc", "compilerVersion": "v0.8.20+commit.a1b2c3d4",
                        "compilerSettings": {"optimizer": {"enabled": True, "runs": 200}, "viaIR": False}},
        "sources": {p: {"content": "..."} for p in sources},
        "runtimeBytecode": rt,
    }
    if metadata:
        body["metadata"] = {"sources": {p: keccaks[p] for p in sources} if with_keccak else
                            {p: {} for p in sources},
                            "settings": {"optimizer": {"enabled": True, "runs": 200}}}
    return body


def vc_from(payload, chain=1, addr="0x" + "11" * 20):
    return parse_sourcify(chain, addr, payload, Source("sourcify", "sourcify", "2026-10-31T00:00:00.000+00:00",
                                                       detail="http 200"))


REF_EXACT = {"ref:a@main": {"contracts/Vault.sol": VAULT, "contracts/MathLib.sol": LIB}}


# -------------------------------------------------------------- 1. exact match
def test_exact_match_by_content_keccak_path_independent():
    vm = classify(vc_from(sourcify_payload(runtime="exact_match")), REF_EXACT)
    assert (vm.status, vm.certainty, vm.ref) == (EXACT_MATCH, VERIFIED, "ref:a@main")
    assert vm.matched_sources == vm.total_sources == 2 and vm.nonfunctional_only is True


# -------------------------------------------------------------- 2. metadata-only difference
def test_metadata_only_difference_is_compiler_match_not_functional():
    vm = classify(vc_from(sourcify_payload(runtime="match", reasons=["cborAuxdata"])), REF_EXACT)
    assert vm.status == COMPILER_MATCH and vm.nonfunctional_only is True
    assert any("metadata" in e for e in vm.evidence)


# -------------------------------------------------------------- 3. immutable difference
def test_immutable_difference_is_nonfunctional():
    vm = classify(vc_from(sourcify_payload(runtime="exact_match", reasons=["immutable"], immutable=True)), REF_EXACT)
    assert vm.status == EXACT_MATCH and vm.nonfunctional_only is True


# -------------------------------------------------------------- 4. linked library
def test_linked_library_is_nonfunctional():
    libs = {"contracts/MathLib.sol:MathLib": "0x" + "ab" * 20}
    vm = classify(vc_from(sourcify_payload(runtime="exact_match", reasons=["library"], libs=libs)), REF_EXACT)
    assert vm.status == EXACT_MATCH and vm.nonfunctional_only is True


# -------------------------------------------------------------- 5. different compiler version (still same sources)
def test_different_compiler_version_does_not_change_source_match():
    p = sourcify_payload(runtime="match", reasons=["cborAuxdata"])
    p["compilation"]["compilerVersion"] = "v0.8.26+commit.deadbeef"
    vm = classify(vc_from(p), REF_EXACT)
    # Sources still correspond; the bytecode-metadata diff is non-functional: COMPILER_MATCH, never a functional delta.
    assert vm.status == COMPILER_MATCH and vm.nonfunctional_only is True
    assert any("0.8.26" in e for e in vm.evidence)


# -------------------------------------------------------------- 6. partial source
def test_partial_source_presence_is_partial_match():
    ref = {"r": {"contracts/Vault.sol": VAULT}}             # MathLib.sol absent at the ref
    vm = classify(vc_from(sourcify_payload(runtime="exact_match")), ref)
    assert (vm.status, vm.matched_sources, vm.total_sources) == (PARTIAL_MATCH, 1, 2)


# -------------------------------------------------------------- 7. source not verified
def test_source_unverified_cannot_match_git():
    vc = vc_from(sourcify_payload(runtime=None, metadata=False))
    assert not is_verified(vc)
    vm = classify(vc, REF_EXACT)
    assert (vm.status, vm.ref, vm.matched_sources) == (SOURCE_UNVERIFIED, None, 0)


def test_sourcify_404_is_verified_fact_of_no_source(monkeypatch):
    vc = fetch_sourcify(1, "0x" + "22" * 20, transport=lambda url: (404, None))
    assert vc.certainty == VERIFIED and not is_verified(vc)
    assert classify(vc, REF_EXACT).status == SOURCE_UNVERIFIED


# -------------------------------------------------------------- 8. no git match
def test_no_git_match_is_not_evidence_of_new_code():
    ref = {"r": {"contracts/Other.sol": VAULT_V2}}
    vm = classify(vc_from(sourcify_payload(runtime="exact_match")), ref)
    assert vm.status == NO_GIT_MATCH and vm.matched_sources == 0
    assert any("not evidence" in e.lower() for e in vm.evidence)


# -------------------------------------------------------------- 9. contradictory: sources at two refs
def test_sources_present_at_two_refs_is_conflicting():
    refs = {"r1": {"a/Vault.sol": VAULT, "a/MathLib.sol": LIB},
            "r2": {"b/Vault.sol": VAULT, "b/MathLib.sol": LIB}}
    vm = classify(vc_from(sourcify_payload(runtime="exact_match")), refs)
    assert vm.status == CONFLICTING and vm.certainty == CONFLICTING


def test_inconsistent_runtime_match_value_is_conflicting():
    vc = vc_from(sourcify_payload(runtime="weird_status"))
    assert vc.certainty == CONFLICTING
    assert classify(vc, REF_EXACT).status == CONFLICTING


# -------------------------------------------------------------- 10. missing compilation data
def test_verified_without_per_source_keccak_is_unknown():
    vm = classify(vc_from(sourcify_payload(runtime="exact_match", with_keccak=True, metadata=False)), REF_EXACT)
    assert vm.status == UNKNOWN            # no metadata => no per-source keccak => cannot match
    vm2 = classify(vc_from(sourcify_payload(runtime="exact_match", with_keccak=False)), REF_EXACT)
    assert vm2.status == UNKNOWN


def test_fetch_transport_failure_is_unknown_not_unverified():
    def boom(url):
        raise TimeoutError("slow")
    vc = fetch_sourcify(1, "0x" + "33" * 20, transport=boom)
    assert vc.certainty == UNKNOWN and classify(vc, REF_EXACT).status == UNKNOWN


# -------------------------------------------------------------- functional change DOES surface
def test_a_real_source_change_is_not_hidden_by_nonfunctional_logic():
    # Deployed sources differ from the ref (V2 has an extra line): NO_GIT_MATCH, and nonfunctional_only stays
    # about bytecode regions only — it never turns a source mismatch into a match.
    ref = {"r": {"contracts/Vault.sol": VAULT_V2, "contracts/MathLib.sol": LIB}}
    vm = classify(vc_from(sourcify_payload(runtime="exact_match")), ref)
    assert vm.status in (PARTIAL_MATCH, NO_GIT_MATCH) and vm.matched_sources < vm.total_sources


# -------------------------------------------------------------- content-match helper + secret safety + store
def test_match_sources_is_by_content_not_path():
    m = match_sources({"x/Vault.sol": K_VAULT, "y/MathLib.sol": K_LIB},
                      {"totally/other/path/V.sol": VAULT, "z/M.sol": LIB}, "ref")
    assert m.all_present and set(m.matched) == {"x/Vault.sol", "y/MathLib.sol"}


def test_store_roundtrip_and_no_secret(tmp_path):
    db = Database(tmp_path / "gsr.db")
    store = DeployStore(db)
    vc = vc_from(sourcify_payload(runtime="exact_match"))
    vm = classify(vc, REF_EXACT)
    store.record_version_match(vc, vm)
    row = store.latest_version_match(vc.chain_id, vc.address)
    assert row["status"] == EXACT_MATCH and row["ref"] == "ref:a@main" and row["nonfunctional_only"] == 1
    assert row["compiler_version"] == "v0.8.20+commit.a1b2c3d4"
    # Row carries provenance; the fixtures contain no RPC URL / API key by construction.
    assert "sourcify" in row["sources"] and "apikey" not in row["sources"].lower()
