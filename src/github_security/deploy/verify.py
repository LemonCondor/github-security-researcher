"""Sourcify v2 verified-source client + parser. Single provider for the MVP (reliable, open, no key).

We use Sourcify only for the deployed-bytecode <-> source link that it has already established (runtimeMatch:
exact_match / match / null) and for the compilation metadata (compiler, settings, per-source keccak256, the
non-functional transformation regions: library / immutable / cborAuxdata / constructorArguments / callProtection).
We never recompile and never reconstruct missing data. Fetch only for addresses the caller has checked are in a
authorized scope (enforced by the caller passing a ScopeAsset-derived address).
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Callable

from ..security.secrets import redact
from ..storage.database import now
from .models import CONFLICTING, UNKNOWN, VERIFIED, Source, VerifiedContract

SOURCIFY_SERVER = "https://sourcify.dev/server"
_FIELDS = "match,creationMatch,runtimeMatch,verifiedAt,compilation,metadata,sources,runtimeBytecode"

Transport = Callable[[str], tuple[int, dict | None]]


def _http(url: str, timeout: int = 25) -> tuple[int, dict | None]:  # pragma: no cover - network
    req = urllib.request.Request(url, headers={"user-agent": "github-security-researcher/deploy-verify",
                                               "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, None
        raise


def fetch_sourcify(chain_id: int, address: str, *, transport: Transport | None = None,
                   server: str = SOURCIFY_SERVER) -> VerifiedContract:
    transport = transport or _http
    addr = address.lower()
    url = f"{server}/v2/contract/{chain_id}/{addr}?fields={urllib.parse.quote(_FIELDS)}"
    ts = now()
    try:
        status, body = transport(url)
    except Exception as e:
        return _unknown(chain_id, addr, ts, f"sourcify fetch failed: {redact(f'{type(e).__name__}: {e}')}")
    src = Source(method="sourcify", ref=f"{server}/v2/contract/{chain_id}/{addr}", observed_at=ts,
                 detail=f"http {status}")
    if status == 404 or body is None:
        # VERIFIED fact: Sourcify positively has no verified source for this address.
        return _empty(chain_id, addr, VERIFIED, [src])
    if not isinstance(body, dict):
        return _unknown(chain_id, addr, ts, "sourcify: malformed response")
    return parse_sourcify(chain_id, addr, body, src)


def _empty(chain_id: int, addr: str, certainty: str, sources: list[Source]) -> VerifiedContract:
    return VerifiedContract(
        chain_id=chain_id, address=addr, provider="sourcify", runtime_match=None, creation_match=None,
        verified_at=None, compiler=None, compiler_version=None, compiler_settings={}, source_keccaks={},
        sources_present=set(), runtime_transform_reasons=set(), linked_libraries={}, has_immutables=False,
        metadata_present=False, certainty=certainty, sources=sources)


def _unknown(chain_id: int, addr: str, ts: str, reason: str) -> VerifiedContract:
    return _empty(chain_id, addr, UNKNOWN, [Source("sourcify", "sourcify", ts, detail=reason)])


def parse_sourcify(chain_id: int, address: str, body: dict, src: Source) -> VerifiedContract:
    comp = body.get("compilation") or {}
    meta = body.get("metadata") or {}
    rt = body.get("runtimeBytecode") or {}
    settings = (comp.get("compilerSettings") or meta.get("settings") or {})

    # Per-source keccak256 from metadata (what solc itself records for each source file).
    source_keccaks: dict[str, str] = {}
    for path, info in (meta.get("sources") or {}).items():
        k = info.get("keccak256") if isinstance(info, dict) else None
        if isinstance(k, str) and k.startswith("0x"):
            source_keccaks[path] = k.lower()
    sources_present = {p for p in (body.get("sources") or {})}

    reasons = {t.get("reason") for t in (rt.get("transformations") or []) if isinstance(t, dict)}
    reasons.discard(None)
    tvals = rt.get("transformationValues") or {}
    libs = tvals.get("libraries") or {}
    has_immutables = bool(rt.get("immutableReferences")) or bool(tvals.get("immutables"))

    runtime_match = body.get("runtimeMatch")
    creation_match = body.get("creationMatch")
    # Contradiction guard: a match status with no recompiled link is inconsistent.
    certainty = VERIFIED
    if runtime_match not in (None, "match", "exact_match"):
        certainty = CONFLICTING

    return VerifiedContract(
        chain_id=chain_id, address=address, provider="sourcify",
        runtime_match=runtime_match, creation_match=creation_match, verified_at=body.get("verifiedAt"),
        compiler=comp.get("compiler"), compiler_version=comp.get("compilerVersion"),
        compiler_settings=settings if isinstance(settings, dict) else {},
        source_keccaks=source_keccaks, sources_present=sources_present,
        runtime_transform_reasons=reasons, linked_libraries=libs if isinstance(libs, dict) else {},
        has_immutables=has_immutables, metadata_present=bool(meta),
        certainty=certainty, sources=[src])


def is_verified(vc: VerifiedContract) -> bool:
    return vc.runtime_match in ("match", "exact_match") or vc.creation_match in ("match", "exact_match")
