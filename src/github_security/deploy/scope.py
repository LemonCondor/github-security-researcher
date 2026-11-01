"""Official program scope -> normalized assets. The scope snapshot is the source of truth for eligibility.

Input: one program object as published by Immunefi (public bounties JSON or the program page data).
Only explicitly listed assets are in scope; a scope "Primacy of Impact" row is NOT an address and never makes
an unlisted contract in scope here. Assets are deduplicated by (chain, address): several listed names for the
same contract are kept as aliases. The same address on two chains stays two assets (programs list each chain).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..storage.database import now
from .chains import is_github_url, parse_explorer_url
from .models import INFERRED, UNKNOWN, VERIFIED, ScopeAsset, Source


@dataclass
class ProgramScope:
    platform: str
    slug: str
    name: str
    max_bounty: float | None
    kyc: bool | None
    scope_sha256: str
    complete: bool                  # True only when the snapshot is the full asset list (not a paginated page)
    fetched_at: str
    source_url: str
    assets: list[ScopeAsset] = field(default_factory=list)

    def contracts(self) -> list[ScopeAsset]:
        return [a for a in self.assets if a.asset_kind == "contract"]

    def lookup(self, chain_id: int | None, address: str | None) -> ScopeAsset | None:
        """Exact (chain, address) match. An asset whose chain is unknown matches on address only and keeps its
        UNKNOWN chain (the caller must not treat that as a chain match)."""
        if not address:
            return None
        address = address.lower()
        fallback = None
        for a in self.contracts():
            if a.address != address:
                continue
            if a.chain_id is not None and a.chain_id == chain_id:
                return a
            if a.chain_id is None:
                fallback = a
        return fallback


def _slugify(text: str) -> str:
    return "-".join("".join(ch.lower() if ch.isalnum() else " " for ch in text).split())


def parse_immunefi_program(program: dict, *, source_url: str, complete: bool = True,
                           fetched_at: str | None = None) -> ProgramScope:
    fetched_at = fetched_at or now()
    canonical = json.dumps(program, sort_keys=True, separators=(",", ":"), default=str)
    sha = hashlib.sha256(canonical.encode()).hexdigest()
    name = str(program.get("project") or program.get("name") or program.get("id") or "unknown")
    slug = str(program.get("id") or program.get("slug") or _slugify(name))
    kyc = program.get("kyc")
    scope = ProgramScope(platform="immunefi", slug=slug, name=name,
                         max_bounty=program.get("maxBounty"), kyc=kyc if isinstance(kyc, bool) else None,
                         scope_sha256=sha, complete=complete, fetched_at=fetched_at, source_url=source_url)
    scope_src = Source(method="immunefi_scope", ref=f"{source_url}#sha256={sha}", observed_at=fetched_at,
                       detail="" if complete else "snapshot marked incomplete")

    merged: dict[str, ScopeAsset] = {}
    for raw in program.get("assets") or []:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "")
        desc = str(raw.get("description") or "").strip()
        added = raw.get("addedAt")
        poi = raw.get("isPrimacyOfImpact")
        poi = poi if isinstance(poi, bool) else None
        atype = str(raw.get("type") or "")

        if atype != "smart_contract":
            kind, chain, addr, chain_cert = "non_contract", None, None, UNKNOWN
        elif is_github_url(url):
            kind, chain, addr, chain_cert = "source_reference", None, None, UNKNOWN
        else:
            chain, addr, host = parse_explorer_url(url)
            if addr is None:
                kind, chain_cert = "incomplete", UNKNOWN
            else:
                kind = "contract"
                chain_cert = INFERRED if chain is not None else UNKNOWN

        key = f"{chain if chain is not None else '?'}:{addr}" if kind == "contract" else f"url:{url}"
        asset_src = Source(method="immunefi_scope_asset", ref=scope_src.ref, observed_at=fetched_at,
                           detail=f"{desc} | {url} | addedAt={added}")
        if key in merged:
            a = merged[key]
            if desc and desc not in a.names:
                a.names.append(desc)
            if url and url not in a.urls:
                a.urls.append(url)
            if added and (a.added_at is None or str(added) < a.added_at):
                a.added_at = str(added)
            if a.is_primacy_of_impact is not None and poi is not None and a.is_primacy_of_impact != poi:
                a.is_primacy_of_impact = None          # listed twice with contradictory flags: not established
                a.sources.append(Source(method="conflict", ref=scope_src.ref, observed_at=fetched_at,
                                        detail="isPrimacyOfImpact differs between duplicate entries"))
            a.sources.append(asset_src)
            continue
        merged[key] = ScopeAsset(
            key=key, asset_kind=kind, chain_id=chain, address=addr, names=[desc] if desc else [],
            urls=[url] if url else [], added_at=str(added) if added else None, is_primacy_of_impact=poi,
            chain_certainty=chain_cert,
            # Presence in the official list is a fact of the snapshot; if the snapshot is incomplete we only
            # know the asset is listed, not that the list we hold is the whole scope.
            certainty=VERIFIED if complete else INFERRED,
            sources=[scope_src, asset_src])
    scope.assets = list(merged.values())
    return scope
