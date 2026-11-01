"""Source <-> git correspondence by CONTENT keccak256 (path-independent), and the final classification.

A verified contract carries, per source file, the keccak256 of its content (solc's own metadata hash). We look
for those exact contents in a candidate git ref by hashing the ref's files. Matching by content, not by path,
sidesteps remapping/path differences. A file-hash match is NOT, on its own, proof the deployed BYTECODE equals
the ref: that link is only as strong as Sourcify's runtimeMatch, and non-functional regions (metadata/auxdata,
immutables, libraries, linking) are tracked separately so later stages never read them as functional changes.
"""
from __future__ import annotations

from .keccak import keccak256_hex
from .models import (COMPILER_MATCH, CONFLICTING, EXACT_MATCH, NO_GIT_MATCH, NONFUNCTIONAL_REASONS, PARTIAL_MATCH,
                     SOURCE_UNVERIFIED, UNKNOWN, VERIFIED, Source, SourceGitMatch, VersionMatch)
from .verify import is_verified


def ref_content_keccaks(ref_blobs: dict[str, bytes]) -> dict[str, str]:
    """keccak256 of each candidate file's raw bytes -> its path (for diagnostics)."""
    out: dict[str, str] = {}
    for path, blob in ref_blobs.items():
        out[path] = keccak256_hex(blob)
    return out


def match_sources(source_keccaks: dict[str, str], ref_blobs: dict[str, bytes], ref: str) -> SourceGitMatch:
    present = set(ref_content_keccaks(ref_blobs).values())
    matched = sorted(p for p, k in source_keccaks.items() if k in present)
    missing = sorted(p for p, k in source_keccaks.items() if k not in present)
    return SourceGitMatch(ref=ref, matched=matched, missing=missing, total=len(source_keccaks))


def classify(vc, ref_blobs_by_ref: dict[str, dict[str, bytes]]) -> VersionMatch:
    """Classify one verified contract against one or more candidate git refs.

    ref_blobs_by_ref: {git_ref: {path: content_bytes}}. Each ref is a snapshot to test the sources against.
    """
    ts = vc.sources[0].observed_at if vc.sources else ""
    base = Source("deploy_match", f"{vc.provider}:{vc.chain_id}:{vc.address}", ts)

    if not is_verified(vc):
        # certainty carries why: UNKNOWN (fetch/parse failed) or CONFLICTING (inconsistent status) propagate;
        # otherwise it is the VERIFIED fact that the explorer has no verified source.
        status = {UNKNOWN: UNKNOWN, CONFLICTING: CONFLICTING}.get(vc.certainty, SOURCE_UNVERIFIED)
        cert = vc.certainty if vc.certainty in (UNKNOWN, CONFLICTING) else VERIFIED
        ev = ["source not verified on the explorer; nothing can be matched to git" if status == SOURCE_UNVERIFIED
              else f"verification state {status}: cannot match sources to git"]
        return VersionMatch(vc.chain_id, vc.address, status, cert, None, 0, 0, None, ev, [*vc.sources, base])

    if not vc.source_keccaks:
        return VersionMatch(vc.chain_id, vc.address, UNKNOWN, UNKNOWN, None, 0, 0, None,
                            ["verified but metadata carried no per-source keccak256"], [*vc.sources, base])

    total = len(vc.source_keccaks)
    matches = {ref: match_sources(vc.source_keccaks, blobs, ref) for ref, blobs in ref_blobs_by_ref.items()}
    full = [m for m in matches.values() if m.all_present]
    partial = [m for m in matches.values() if m.any_present and not m.all_present]

    # Non-functional-only: the deployed bytecode differs from a clean recompile of these exact sources only in
    # regions Sourcify labels non-functional, i.e. runtimeMatch == exact_match, or == match (metadata/auxdata).
    reasons = vc.runtime_transform_reasons
    functional_reasons = reasons - NONFUNCTIONAL_REASONS
    nonfunctional_only = (vc.runtime_match in ("exact_match", "match")) and not functional_reasons

    if len(full) > 1:
        return VersionMatch(vc.chain_id, vc.address, CONFLICTING, CONFLICTING, None, total, total, nonfunctional_only,
                            [f"sources fully present at several distinct refs: {sorted(m.ref for m in full)}"],
                            [*vc.sources, base])
    if full:
        m = full[0]
        exact = vc.runtime_match == "exact_match"
        status = EXACT_MATCH if exact else COMPILER_MATCH
        ev = [f"all {total} compilation sources present at {m.ref} (content keccak256)",
              f"Sourcify runtimeMatch={vc.runtime_match}",
              f"compiler={vc.compiler} {vc.compiler_version}"]
        if not exact:
            ev.append("bytecode matches except metadata/auxdata (COMPILER_MATCH, not functional)")
        if reasons:
            ev.append(f"non-functional regions: {sorted(reasons)}")
        return VersionMatch(vc.chain_id, vc.address, status, VERIFIED, m.ref, total, total, nonfunctional_only,
                            ev, [*vc.sources, base])
    if partial:
        best = max(partial, key=lambda m: len(m.matched))
        ev = [f"{len(best.matched)}/{total} sources present at {best.ref}; missing: {best.missing[:5]}",
              "a subset match is not a version correspondence"]
        return VersionMatch(vc.chain_id, vc.address, PARTIAL_MATCH, VERIFIED, best.ref, len(best.matched), total,
                            nonfunctional_only, ev, [*vc.sources, base])
    ev = ["verified source does not match any candidate git ref by content keccak256",
          "NO_GIT_MATCH is not evidence the code is new or unaudited; the audited ref may be absent/untested here"]
    return VersionMatch(vc.chain_id, vc.address, NO_GIT_MATCH, VERIFIED, None, 0, total, nonfunctional_only, ev,
                        [*vc.sources, base])
