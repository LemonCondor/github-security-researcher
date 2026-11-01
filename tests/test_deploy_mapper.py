"""Deployment mapper (deploy milestone 1): deterministic, offline. A fake read-only chain stands in for RPC.

All addresses are fictional fixtures; no real protocol is contacted.
"""
import json
import sqlite3
from pathlib import Path

import pytest

from github_security.deploy import bytecode
from github_security.deploy.chains import normalize_address, parse_explorer_url
from github_security.deploy.mapper import (EIP1967_ADMIN_SLOT, EIP1967_BEACON_SLOT, EIP1967_IMPL_SLOT,
                                           map_address, map_scope)
from github_security.deploy.models import (AMBIGUOUS, CHAIN_UNKNOWN, CONFLICTING, DIRECT, IMPLEMENTATION_NO_CODE,
                                           INFERRED, KIND_UNKNOWN, MAPPED, NO_RPC, NOT_DEPLOYED, NOT_IN_SCOPE,
                                           NOT_RESOLVED, PROXY_EIP1967, RESOLVED, RPC_ERROR, UNKNOWN, UNSUPPORTED,
                                           VERIFIED, WRONG_NETWORK)
from github_security.deploy.rpc import ALLOWED_METHODS, RpcClient, RpcError, endpoint_label
from github_security.deploy.scope import parse_immunefi_program
from github_security.deploy.store import DeployStore
from github_security.storage.database import SCHEMA_VERSION, Database

FIX = Path(__file__).parent / "fixtures" / "deploy" / "immunefi_program.json"
A = {k: "0x" + k * 40 for k in "123456789a"}          # fictional addresses
IMPL = "0x" + "bb" * 20
IMPL_MISSING = "0x" + "cc" * 20
BEACON = "0x" + "dd" * 20
ADMIN = "0x" + "ee" * 20

# CBOR-like trailing metadata whose bytes include 0xf4: must be stripped, not read as DELEGATECALL
META = bytes([0xA2]) + b"\xf4" * 10
META = META + len(META).to_bytes(2, "big")
DIRECT_CODE = bytes.fromhex("6080604052") + bytes([0x7F]) + b"\xf4" * 32 + bytes.fromhex("600160005500") + META
PROXY_CODE = bytes.fromhex("6080604052365f5f375f5f365f7f") + bytes(32) + bytes.fromhex("545af43d5f5f3e00") + META
IMPL_CODE = bytes.fromhex("608060405260006000f3") + META
MINIMAL_CODE = (bytes.fromhex("363d3d373d3d3d363d73") + bytes.fromhex("bb" * 20)
                + bytes.fromhex("5af43d82803e903d91602b57fd5bf3"))


def _word(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0")


class FakeChain:
    """Answers only the read-only methods; records every call."""

    def __init__(self, chain_id=1, block=19_000_000, code=None, storage=None, fail=None):
        self.chain_id, self.block = chain_id, block
        self.code = code or {}
        self.storage = storage or {}
        self.fail = fail or set()
        self.calls = []

    def __call__(self, url, payload):
        m, p = payload["method"], payload["params"]
        self.calls.append(m)
        if m in self.fail:
            return {"jsonrpc": "2.0", "id": payload["id"], "error": {"code": -32000, "message": "upstream timeout"}}
        if m == "eth_chainId":
            r = hex(self.chain_id)
        elif m == "eth_blockNumber":
            r = hex(self.block)
        elif m == "eth_getCode":
            r = "0x" + self.code.get(p[0].lower(), b"").hex()
        elif m == "eth_getStorageAt":
            r = self.storage.get((p[0].lower(), p[1]), "0x" + "00" * 32)
        else:
            raise AssertionError(f"unexpected method reached transport: {m}")
        return {"jsonrpc": "2.0", "id": payload["id"], "result": r}


def standard_chain(**kw) -> FakeChain:
    code = {A["1"]: DIRECT_CODE, A["2"]: PROXY_CODE, IMPL: IMPL_CODE, A["3"]: PROXY_CODE, A["4"]: PROXY_CODE,
            A["5"]: PROXY_CODE, A["6"]: MINIMAL_CODE, A["7"]: PROXY_CODE}
    storage = {(A["2"], EIP1967_IMPL_SLOT): _word(IMPL), (A["2"], EIP1967_ADMIN_SLOT): _word(ADMIN),
               (A["3"], EIP1967_IMPL_SLOT): _word(IMPL_MISSING),
               (A["4"], EIP1967_IMPL_SLOT): _word(IMPL), (A["4"], EIP1967_BEACON_SLOT): _word(BEACON),
               (A["5"], EIP1967_BEACON_SLOT): _word(BEACON)}
    return FakeChain(code=code, storage=storage, **kw)


@pytest.fixture
def scope():
    return parse_immunefi_program(json.loads(FIX.read_text()), source_url="fixture://immunefi_program.json",
                                  fetched_at="2026-10-31T00:00:00.000+00:00")


def rpc(chain: FakeChain, url="https://rpc.example.invalid/v2/SECRETKEY0123456789") -> RpcClient:
    return RpcClient(url, transport=chain)


# ---------------------------------------------------------------- scope normalization
def test_scope_parsing_normalizes_and_dedupes(scope):
    contracts = {a.address: a for a in scope.contracts()}
    assert set(contracts) == {A[k] for k in "123456789a"}
    alias = contracts[A["2"]]
    assert alias.names == ["Strategy Proxy", "Strategy Proxy (alias)"] and len(alias.urls) == 2
    assert alias.chain_id == 1 and alias.chain_certainty == INFERRED and alias.certainty == VERIFIED
    kinds = sorted(a.asset_kind for a in scope.assets)
    assert kinds.count("source_reference") == 1 and kinds.count("non_contract") == 1
    assert kinds.count("incomplete") == 2          # explorer page without address + "Primacy Of Impact" row
    assert scope.kyc is False and scope.max_bounty == 100000 and len(scope.scope_sha256) == 64


def test_chain_table_is_closed_and_addresses_strict():
    assert parse_explorer_url("https://basescan.org/address/" + A["9"])[:2] == (8453, A["9"])
    assert parse_explorer_url("https://www.oklink.com/xlayer/address/" + A["9"])[:2] == (196, A["9"])
    assert parse_explorer_url("https://somechain.blockscout.com/address/" + A["8"])[:2] == (None, A["8"])
    assert parse_explorer_url("https://www.oklink.com/unknownchain/address/" + A["8"])[0] is None
    assert normalize_address("0x" + "AB" * 20) == "0x" + "ab" * 20
    assert normalize_address("0x123") is None and normalize_address(None) is None


# ---------------------------------------------------------------- 1. direct contract
def test_direct_contract_verified_and_push_metadata_bytes_ignored(scope):
    assert bytecode.delegating_opcodes(DIRECT_CODE) == set()      # 0xf4 only inside PUSH32 data and metadata
    r = map_address(scope, 1, A["1"], [rpc(standard_chain())])
    assert (r.status, r.kind, r.certainty, r.proxy) == (MAPPED, DIRECT, VERIFIED, None)
    assert r.block == 19_000_000 and r.code_size == len(DIRECT_CODE) and len(r.code_sha256) == 64


# ---------------------------------------------------------------- 2. EIP-1967 proxy
def test_eip1967_proxy_resolves_implementation(scope):
    r = map_address(scope, 1, A["2"], [rpc(standard_chain())])
    assert (r.status, r.kind, r.certainty) == (MAPPED, PROXY_EIP1967, VERIFIED)
    p = r.proxy
    assert (p.standard, p.resolution, p.implementation, p.implementation_has_code, p.admin, p.certainty) == \
        ("EIP1967", RESOLVED, IMPL, True, ADMIN, VERIFIED)


# ---------------------------------------------------------------- 3. implementation absent
def test_implementation_without_code_is_reported_not_resolved(scope):
    r = map_address(scope, 1, A["3"], [rpc(standard_chain())])
    assert r.kind == PROXY_EIP1967
    assert (r.proxy.resolution, r.proxy.implementation, r.proxy.implementation_has_code) == \
        (IMPLEMENTATION_NO_CODE, IMPL_MISSING, False)
    assert "no code" in r.reasons[0]


# ---------------------------------------------------------------- 4. ambiguous / unsupported resolution
def test_ambiguous_proxy_is_conflicting_never_guessed(scope):
    r = map_address(scope, 1, A["4"], [rpc(standard_chain())])
    assert (r.kind, r.certainty) == (KIND_UNKNOWN, CONFLICTING)
    assert (r.proxy.standard, r.proxy.resolution) == ("MULTIPLE", AMBIGUOUS)


def test_unsupported_mechanisms_are_never_presented_as_direct(scope):
    chain = standard_chain()
    beacon = map_address(scope, 1, A["5"], [rpc(chain)])
    minimal = map_address(scope, 1, A["6"], [rpc(chain)])
    delegating = map_address(scope, 1, A["7"], [rpc(chain)])
    assert (beacon.kind, beacon.proxy.standard, beacon.proxy.resolution) == \
        (UNSUPPORTED, "EIP1967_BEACON", NOT_RESOLVED)
    assert (minimal.kind, minimal.proxy.standard, minimal.proxy.implementation) == (UNSUPPORTED, "EIP1167", IMPL)
    assert (delegating.kind, delegating.certainty, delegating.proxy) == (KIND_UNKNOWN, UNKNOWN, None)
    assert all(r.kind != DIRECT for r in (beacon, minimal, delegating))


# ---------------------------------------------------------------- 5. out of scope
def test_out_of_scope_address_is_never_read(scope):
    chain = standard_chain()
    r = map_address(scope, 1, "0x" + "12" * 20, [rpc(chain)])
    assert (r.status, r.certainty) == (NOT_IN_SCOPE, VERIFIED) and chain.calls == []


def test_absence_from_incomplete_snapshot_is_unknown_not_negative():
    partial = parse_immunefi_program(json.loads(FIX.read_text()), source_url="fixture://page-1", complete=False)
    r = map_address(partial, 1, "0x" + "12" * 20, [])
    assert (r.status, r.certainty) == (NOT_IN_SCOPE, UNKNOWN)
    assert all(a.certainty == INFERRED for a in partial.contracts())


# ---------------------------------------------------------------- 6. incorrect network
def test_wrong_network_endpoint_stops_before_reading_code(scope):
    chain = standard_chain(chain_id=1)                      # endpoint configured for Base answers mainnet
    r = map_address(scope, 8453, A["9"], [rpc(chain)])
    assert (r.status, r.certainty) == (WRONG_NETWORK, CONFLICTING)
    assert chain.calls == ["eth_chainId"]


def test_address_listed_on_another_chain_is_out_of_scope_there(scope):
    assert map_address(scope, 8453, A["1"], []).status == NOT_IN_SCOPE


def test_unrecognised_explorer_gives_chain_unknown_without_rpc(scope):
    r = map_address(scope, None, A["8"], [])
    assert (r.status, r.certainty) == (CHAIN_UNKNOWN, UNKNOWN)


# ---------------------------------------------------------------- 7. contradictory data
def test_endpoints_disagreeing_at_pinned_block_is_conflicting(scope):
    honest = standard_chain()
    other = standard_chain()
    other.storage[(A["2"], EIP1967_IMPL_SLOT)] = _word("0x" + "ab" * 20)
    r = map_address(scope, 1, A["2"], [rpc(honest), rpc(other, "https://other.example.invalid")])
    assert (r.kind, r.certainty, r.proxy) == (KIND_UNKNOWN, CONFLICTING, None)


def test_duplicate_scope_entries_with_contradictory_flags_are_not_established(scope):
    alias = scope.lookup(1, A["2"])
    assert alias.is_primacy_of_impact is None
    assert any(s.method == "conflict" for s in alias.sources)


# ---------------------------------------------------------------- 8. incomplete data
def test_failed_read_is_rpc_error_never_direct(scope):
    r = map_address(scope, 1, A["1"], [rpc(standard_chain(fail={"eth_getStorageAt"}))])
    assert (r.status, r.kind, r.certainty) == (RPC_ERROR, None, UNKNOWN)


def test_no_endpoint_and_missing_code_are_explicit(scope):
    assert map_address(scope, 1, A["1"], []).status == NO_RPC
    r = map_address(scope, 1, A["a"], [rpc(standard_chain())])
    assert (r.status, r.certainty) == (NOT_DEPLOYED, VERIFIED)


def test_non_address_storage_word_is_unknown(scope):
    chain = standard_chain()
    chain.storage[(A["1"], EIP1967_IMPL_SLOT)] = "0x" + "ff" * 32
    r = map_address(scope, 1, A["1"], [rpc(chain)])
    assert (r.kind, r.certainty) == (KIND_UNKNOWN, UNKNOWN)


# ---------------------------------------------------------------- read-only + secrets
def test_rpc_refuses_every_non_read_only_method():
    chain = FakeChain()
    client = rpc(chain)
    for m in ("eth_sendRawTransaction", "eth_sendTransaction", "eth_call", "personal_sign", "eth_sign"):
        with pytest.raises(RpcError):
            client.call(m, [])
    assert chain.calls == [] and ALLOWED_METHODS == {"eth_chainId", "eth_blockNumber", "eth_getCode",
                                                     "eth_getStorageAt"}


def test_rpc_url_secrets_never_reach_sources_or_db(scope, tmp_path):
    key = "SECRETKEY0123456789"
    assert endpoint_label(f"https://rpc.example.invalid/v2/{key}?apikey={key}") == "https://rpc.example.invalid"
    db = Database(tmp_path / "gsr.db")
    store = DeployStore(db)
    pid = store.upsert_program(scope)
    for r in map_scope(scope, lambda cid: [rpc(standard_chain())] if cid == 1 else []):
        store.record(pid, r)
    dump = "\n".join(db.conn.iterdump())
    assert key not in dump and "rpc.example.invalid" in dump


# ---------------------------------------------------------------- storage
def test_store_roundtrip_append_only_and_constraints(scope, tmp_path):
    db = Database(tmp_path / "gsr.db")
    store = DeployStore(db)
    pid = store.upsert_program(scope)
    assert store.upsert_program(scope) == pid                         # idempotent upsert
    chain = standard_chain()
    store.record(pid, map_address(scope, 1, A["2"], [rpc(chain)]))
    chain.block += 100                                                # later observation: upgrade appended
    chain.storage[(A["2"], EIP1967_IMPL_SLOT)] = _word(IMPL_MISSING)
    store.record(pid, map_address(scope, 1, A["2"], [rpc(chain)]))
    rows = db.conn.execute("SELECT block, kind, certainty, asset_id FROM deploy_deployments ORDER BY id").fetchall()
    assert [tuple(r)[:3] for r in rows] == [(19_000_000, PROXY_EIP1967, VERIFIED), (19_000_100, PROXY_EIP1967,
                                                                                     VERIFIED)]
    assert rows[0]["asset_id"] is not None
    latest = store.latest(1, A["2"])
    assert (latest["resolution"], latest["implementation"]) == (IMPLEMENTATION_NO_CODE, IMPL_MISSING)
    srcs = json.loads(latest["sources"])
    assert any(s["method"].startswith("rpc:") and s.get("block") == 19_000_100 for s in srcs)
    with pytest.raises(sqlite3.IntegrityError):
        db.conn.execute("INSERT INTO deploy_deployments(status, certainty, observed_at) VALUES ('MAPPED','SURE','x')")


def test_existing_database_gains_tables_without_version_change(tmp_path):
    path = tmp_path / "old.db"
    Database(path).close()
    db = Database(path)
    names = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"deploy_programs", "deploy_assets", "deploy_deployments", "deploy_proxies"} <= names
    assert db.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
