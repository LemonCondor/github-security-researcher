"""Deployment mapper (spec §3, first milestone): scope -> network -> pinned block -> code -> proxy slots.

Supported in this version: direct contracts and EIP-1967 implementation-slot proxies (transparent / UUPS).
Recognised but NOT resolved (UNSUPPORTED, never presented as DIRECT): EIP-1967 beacon proxies, EIP-1167 minimal
proxies, legacy OpenZeppelin (zos) implementation slot. Diamonds and any other delegating contract without a
supported slot are UNKNOWN. Several mechanisms at once is AMBIGUOUS / CONFLICTING.

Every read is done at one pinned block on every configured endpoint; disagreement between endpoints yields
CONFLICTING. A failed read yields UNKNOWN: an unknown is never turned into "not a proxy" or "not deployed".
Read-only by construction (see rpc.ALLOWED_METHODS). Nothing here executes contract code.
"""
from __future__ import annotations

from typing import Callable

from ..storage.database import now
from .bytecode import code_sha256, delegating_opcodes, eip1167_target
from .chains import normalize_address
from .models import (AMBIGUOUS, CHAIN_UNKNOWN, CONFLICTING, DIRECT, IMPLEMENTATION_NO_CODE, KIND_UNKNOWN, MAPPED,
                     NO_RPC, NOT_DEPLOYED, NOT_IN_SCOPE, NOT_RESOLVED, PROXY_EIP1967, RESOLVED, RPC_ERROR,
                     UNKNOWN, UNSUPPORTED, VERIFIED, WRONG_NETWORK, MappingResult, ProxyRelationship, Source)
from .rpc import RpcClient, RpcError
from .scope import ProgramScope

# EIP-1967: bytes32(uint256(keccak256('eip1967.proxy.<name>')) - 1)
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
# keccak256("org.zeppelinos.proxy.implementation") -- pre-EIP-1967 OpenZeppelin proxies
LEGACY_ZOS_IMPL_SLOT = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
_SLOTS = {"impl": EIP1967_IMPL_SLOT, "beacon": EIP1967_BEACON_SLOT, "admin": EIP1967_ADMIN_SLOT,
          "legacy": LEGACY_ZOS_IMPL_SLOT}


def _word_to_address(word: int) -> str | None:
    """A storage word holding an address has its upper 12 bytes zero. Returns None for zero."""
    if word == 0 or word >> 160:
        return None
    return "0x" + word.to_bytes(20, "big").hex()


def _agree(values: list) -> bool:
    return all(v == values[0] for v in values[1:])


def map_address(scope: ProgramScope, chain_id: int | None, address: str | None,
                rpcs: list[RpcClient]) -> MappingResult:
    ts = now()
    addr = normalize_address(address)
    asset = scope.lookup(chain_id, addr) if addr else None
    if asset is None:
        # Absence from a complete official list is the fact; from an incomplete snapshot it proves nothing.
        cert = VERIFIED if scope.complete else UNKNOWN
        reason = "invalid address" if addr is None else f"not listed for chain {chain_id} in the scope snapshot"
        return MappingResult(chain_id, addr, NOT_IN_SCOPE, None, cert, reasons=[reason],
                             sources=[Source("immunefi_scope", f"{scope.source_url}#sha256={scope.scope_sha256}",
                                             ts)])
    res = MappingResult(asset.chain_id, addr, MAPPED, None, UNKNOWN, asset_key=asset.key,
                        sources=list(asset.sources))
    if asset.chain_id is None:
        res.status, res.reasons = CHAIN_UNKNOWN, ["network not determinable from the scope entry"]
        return res
    if not rpcs:
        res.status, res.reasons = NO_RPC, [f"no RPC endpoint configured for chain {asset.chain_id}"]
        return res

    try:
        for rpc in rpcs:
            got = rpc.chain_id()
            res.sources.append(Source("rpc:eth_chainId", rpc.label, ts, detail=str(got)))
            if got != asset.chain_id:
                res.status, res.certainty = WRONG_NETWORK, CONFLICTING
                res.reasons = [f"{rpc.label} reports chain {got}, scope asset is on chain {asset.chain_id}"]
                return res
        block = rpcs[0].block_number()
        res.block = block
        codes, slots = [], []
        for rpc in rpcs:
            codes.append(rpc.get_code(addr, block))
            slots.append({k: rpc.get_storage(addr, s, block) for k, s in _SLOTS.items()})
            res.sources.append(Source("rpc:eth_getCode+eth_getStorageAt", rpc.label, ts, block=block))
    except RpcError as e:
        res.status, res.certainty, res.reasons = RPC_ERROR, UNKNOWN, [str(e)]
        return res

    if not _agree(codes) or not _agree(slots):
        res.kind, res.certainty = KIND_UNKNOWN, CONFLICTING
        res.reasons = [f"RPC endpoints disagree at block {block}"]
        return res

    code, words = codes[0], slots[0]
    if not code:
        res.status, res.certainty = NOT_DEPLOYED, VERIFIED
        res.reasons = [f"no runtime code at block {block}"]
        return res
    res.code_size, res.code_sha256 = len(code), code_sha256(code)

    malformed = [k for k, w in words.items() if w and _word_to_address(w) is None]
    if malformed:
        res.kind, res.certainty = KIND_UNKNOWN, UNKNOWN
        res.reasons = [f"slot(s) {malformed} hold a non-address value"]
        return res
    impl, beacon = _word_to_address(words["impl"]), _word_to_address(words["beacon"])
    admin, legacy = _word_to_address(words["admin"]), _word_to_address(words["legacy"])
    minimal = eip1167_target(code)
    mechs = [m for m, on in (("EIP1967", impl), ("EIP1967_BEACON", beacon), ("LEGACY_ZOS", legacy),
                             ("EIP1167", minimal)) if on]
    rpc_src = [s for s in res.sources if s.method.startswith("rpc:")]

    if len(mechs) > 1:
        res.kind, res.certainty = KIND_UNKNOWN, CONFLICTING
        res.reasons = [f"several proxy mechanisms set at once: {mechs}"]
        res.proxy = ProxyRelationship("MULTIPLE", AMBIGUOUS, impl, None, beacon, admin, CONFLICTING, rpc_src)
        return res

    if mechs == ["EIP1967"]:
        try:
            impl_codes = [rpc.get_code(impl, block) for rpc in rpcs]
        except RpcError as e:
            res.kind, res.certainty, res.reasons = PROXY_EIP1967, VERIFIED, [f"implementation read failed: {e}"]
            res.proxy = ProxyRelationship("EIP1967", NOT_RESOLVED, impl, None, None, admin, UNKNOWN, rpc_src)
            return res
        if not _agree(impl_codes):
            res.kind, res.certainty = PROXY_EIP1967, VERIFIED
            res.reasons = ["endpoints disagree on implementation code"]
            res.proxy = ProxyRelationship("EIP1967", NOT_RESOLVED, impl, None, None, admin, CONFLICTING, rpc_src)
            return res
        has_code = bool(impl_codes[0])
        res.kind, res.certainty = PROXY_EIP1967, VERIFIED
        res.proxy = ProxyRelationship("EIP1967", RESOLVED if has_code else IMPLEMENTATION_NO_CODE, impl, has_code,
                                      None, admin, VERIFIED, rpc_src)
        if not has_code:
            res.reasons = [f"implementation slot points to {impl}, which has no code at block {block}"]
        return res

    if mechs:   # exactly one recognised-but-unsupported mechanism
        m = mechs[0]
        res.kind, res.certainty = UNSUPPORTED, VERIFIED
        res.reasons = [f"{m} proxy recognised; resolution not supported in this version"]
        res.proxy = ProxyRelationship(m, NOT_RESOLVED, impl or legacy or minimal, None, beacon, admin, VERIFIED,
                                      rpc_src)
        return res

    ops = delegating_opcodes(code)
    if ops:
        res.kind, res.certainty = KIND_UNKNOWN, UNKNOWN
        res.reasons = [f"{sorted(ops)} present without a supported proxy slot (custom proxy, diamond or library "
                       "calls): not classified"]
        return res
    res.kind, res.certainty = DIRECT, VERIFIED
    res.reasons = ["no DELEGATECALL/CALLCODE in runtime code and no proxy slot set"]
    return res


def map_scope(scope: ProgramScope,
              rpcs_for: Callable[[int], list[RpcClient]]) -> list[MappingResult]:
    """Map every listed contract of the scope. `rpcs_for(chain_id)` returns the endpoints for that chain."""
    out = []
    for asset in scope.contracts():
        rpcs = rpcs_for(asset.chain_id) if asset.chain_id is not None else []
        out.append(map_address(scope, asset.chain_id, asset.address, rpcs))
    return out
