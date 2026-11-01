"""D5 delta engine: deterministic functional diff between the audited and the deployed source of a file,
classification into the five categories, a funds-proximity indicator, an evidence-chain gate with STOP
conditions, and an explainable multi-axis ranking. No LLM.

The engine refuses to turn an uncertain delta into an opportunity: a candidate is PRIORITIZED only when the
whole D1-D4 evidence chain holds AND the delta is not already covered by an audit; otherwise it is UNCERTAIN
or BLOCKED, whatever the category priority.
"""
from __future__ import annotations

from .models import (ACCOUNTING_OR_ASSET_CONVERSION_CHANGED, AuditCoverage, CONFLICTING, DIRECT,
                     DIRECT_USER_FUNDS_PATH, EXACT_MATCH, COMPILER_MATCH, FUNCTION_PERMISSIONLESS, FUNDS_UNKNOWN,
                     FunctionDelta, MAPPED, NO_IDENTIFIED_FUNDS_PATH, PERMISSION_RELAXATION, PROXY_EIP1967,
                     RESOLVED, RankBreakdown, Source, TC_BLOCKED, TC_NO_FUNCTIONAL_DELTA, TC_PRIORITIZED,
                     TC_UNCERTAIN, TOLERANCE_OR_THRESHOLD_CHANGED, TriageCandidate, UNKNOWN, VALIDATION_REMOVED_OR_WEAKENED,
                     VERIFIED)
from .models import INDIRECT_USER_FUNDS_PATH
from .solfn import FnFacts, function_facts, funds_proximity, parse_source

_VIS_RANK = {"private": 0, "internal": 1, "": 2, "public": 3, "external": 3}
_CAT_PRIORITY = {FUNCTION_PERMISSIONLESS: 1.0, PERMISSION_RELAXATION: 0.85, VALIDATION_REMOVED_OR_WEAKENED: 0.8,
                 ACCOUNTING_OR_ASSET_CONVERSION_CHANGED: 0.7, TOLERANCE_OR_THRESHOLD_CHANGED: 0.6}


def _caller_gates(f: FnFacts) -> int:
    return len(f.access_modifiers) + (1 if f.has_sender_check else 0)


def classify_function(old: FnFacts | None, new: FnFacts | None,
                      new_facts: dict | None = None) -> FunctionDelta | None:
    if old is None and new is None:
        return None
    sig = (new or old).signature
    if old is None:
        fd = FunctionDelta(sig, "added", evidence=[f"function absent in audited version, present in deployed"])
        _tag_categories_added(new, fd)
        fd.funds = _funds(new, new_facts)
        return fd
    if new is None:
        return FunctionDelta(sig, "removed", evidence=["function present in audited version, removed in deployed"])
    if old.norm_body == new.norm_body and old.access_modifiers == new.access_modifiers and \
       old.visibility == new.visibility:
        return FunctionDelta(sig, "unchanged")   # comment/whitespace/reorder only

    fd = FunctionDelta(sig, "changed")
    og, ng = _caller_gates(old), _caller_gates(new)
    removed_mods = set(old.access_modifiers) - set(new.access_modifiers)
    if og >= 1 and ng == 0:
        fd.categories.append(FUNCTION_PERMISSIONLESS)
        fd.evidence.append(f"caller gates removed entirely: {sorted(set(old.access_modifiers))}"
                           f"{' + sender check' if old.has_sender_check else ''} -> none")
    elif removed_mods or (old.has_sender_check and not new.has_sender_check) or \
            _VIS_RANK[new.visibility] > _VIS_RANK[old.visibility]:
        fd.categories.append(PERMISSION_RELAXATION)
        if removed_mods:
            fd.evidence.append(f"access modifier(s) removed: {sorted(removed_mods)}")
        if old.has_sender_check and not new.has_sender_check:
            fd.evidence.append("msg.sender/role check removed from body")
        if _VIS_RANK[new.visibility] > _VIS_RANK[old.visibility]:
            fd.evidence.append(f"visibility widened: {old.visibility or 'default'} -> {new.visibility or 'default'}")

    removed_guards = set(old.guards) - set(new.guards)
    caller_guard = lambda g: ("msg.sender" in g.replace(" ", "")) or ("tx.origin" in g.replace(" ", ""))
    non_caller_removed = {g for g in removed_guards if not caller_guard(g)}
    if len(new.guards) < len(old.guards) and non_caller_removed:
        fd.categories.append(VALIDATION_REMOVED_OR_WEAKENED)
        fd.evidence.append(f"guard(s) removed: {sorted(list(non_caller_removed))[:3]}")

    if set(old.numeric_comparisons) != set(new.numeric_comparisons):
        added = set(new.numeric_comparisons) - set(old.numeric_comparisons)
        removed = set(old.numeric_comparisons) - set(new.numeric_comparisons)
        # only a threshold change (not merely guards moving around): operator or literal differs
        if added or removed:
            fd.categories.append(TOLERANCE_OR_THRESHOLD_CHANGED)
            fd.evidence.append(f"numeric comparison change: -{sorted(removed)} +{sorted(added)}")

    if set(old.arithmetic) != set(new.arithmetic):
        fd.categories.append(ACCOUNTING_OR_ASSET_CONVERSION_CHANGED)
        diff = (set(new.arithmetic) ^ set(old.arithmetic))
        fd.evidence.append(f"arithmetic/conversion statement(s) changed: {sorted(list(diff))[:3]}")

    fd.funds = _funds(new, new_facts)
    if not fd.categories:
        # bodies differ but no category matched: a functional change we cannot categorise -> keep as changed,
        # no category, never silently dropped.
        fd.evidence.append("body changed but no category matched (uncategorised functional change)")
    return fd


def _tag_categories_added(f: FnFacts, fd: FunctionDelta) -> None:
    if _caller_gates(f) == 0 and f.changes_state:
        fd.categories.append(PERMISSION_RELAXATION)
        fd.evidence.append("new state-changing function with no caller gate")


def _funds(f: FnFacts | None, new_facts: dict | None = None) -> str:
    if f is None:
        return FUNDS_UNKNOWN
    if new_facts is not None:
        return funds_proximity(f.signature, new_facts)   # D7: static intra-file call graph
    # fallback (no file context): direct transfer / view-pure only, never guessed
    if f.has_value_transfer:
        return DIRECT_USER_FUNDS_PATH
    if not f.changes_state and not f.has_value_transfer:
        return NO_IDENTIFIED_FUNDS_PATH
    return FUNDS_UNKNOWN            # changes state but no transfer here: not guessed


def diff_sources(audited_src: str, deployed_src: str) -> list[FunctionDelta]:
    old = function_facts(parse_source(audited_src, "audited.sol"))
    new = function_facts(parse_source(deployed_src, "deployed.sol"))
    out: list[FunctionDelta] = []
    for sig in sorted(set(old) | set(new)):
        fd = classify_function(old.get(sig), new.get(sig), new_facts=new)
        if fd and fd.change != "unchanged":
            out.append(fd)
    return out


# ------------------------------------------------------------------ evidence-chain gate + ranking
def _stop_reasons(mapping, verified, version_match, coverage) -> list[str]:
    stop = []
    if mapping is not None:
        if mapping.status != MAPPED:
            stop.append(f"deployment status {mapping.status}")
        elif mapping.kind == PROXY_EIP1967 and (mapping.proxy is None or mapping.proxy.resolution != RESOLVED):
            stop.append("active implementation not resolved")
        elif mapping.kind not in (DIRECT, PROXY_EIP1967):
            stop.append(f"contract kind {mapping.kind}: not a supported deployed target")
    if version_match is not None:
        if version_match.status not in (EXACT_MATCH, COMPILER_MATCH):
            stop.append(f"source<->git match {version_match.status}: audited/deployed diff not reliable")
        elif not version_match.ref:
            stop.append("no reference version identified")
    if coverage is not None and coverage.status == "EXPLICIT_DELTA" and \
       coverage.doc_state in ("REVIEWED", "FINDING_REPORTED", "FIX_VERIFIED"):
        stop.append(f"delta already covered by audit (doc_state={coverage.doc_state})")
    return stop


def _rank(deltas, mapping, verified, version_match, coverage, funds) -> RankBreakdown:
    rb = RankBreakdown()
    rb.delta_priority = max((_CAT_PRIORITY.get(c, 0.3) for d in deltas for c in d.categories), default=0.0)
    certs = [getattr(x, "certainty", UNKNOWN) for x in (mapping, version_match, coverage) if x is not None]
    rb.fact_certainty = 1.0 if certs and all(c == VERIFIED for c in certs) else (0.5 if certs else 0.0)
    if coverage is None:
        rb.audit_coverage = 0.0
    elif coverage.status in ("PRIOR_VERSION_ONLY", "UNKNOWN", "PRIVATE_UNKNOWN"):
        rb.audit_coverage = 1.0            # NOT covered / unknown => more interesting
    elif coverage.status == "PARTIAL":
        rb.audit_coverage = 0.6
    else:
        rb.audit_coverage = 0.1            # EXPLICIT_DELTA covered
    rb.funds_proximity = {DIRECT_USER_FUNDS_PATH: 1.0, INDIRECT_USER_FUNDS_PATH: 0.7, FUNDS_UNKNOWN: 0.4,
                          NO_IDENTIFIED_FUNDS_PATH: 0.0}.get(funds, 0.3)
    rb.validation_capability = 0.5         # static-only reproducibility for this milestone
    return rb


def _overall_funds(deltas) -> str:
    order = [DIRECT_USER_FUNDS_PATH, INDIRECT_USER_FUNDS_PATH, FUNDS_UNKNOWN, NO_IDENTIFIED_FUNDS_PATH]
    best = NO_IDENTIFIED_FUNDS_PATH
    for d in deltas:
        if d.funds in order and order.index(d.funds) < order.index(best):
            best = d.funds
    return best if deltas else FUNDS_UNKNOWN


def build_candidate(chain_id: int, address: str, file: str, audited_src: str, deployed_src: str, *,
                    mapping=None, verified=None, version_match=None, coverage: AuditCoverage | None = None,
                    observed_at: str = "") -> TriageCandidate:
    deltas = diff_sources(audited_src, deployed_src)
    src = [Source("delta_engine", f"{file}", observed_at,
                  detail=f"audited={getattr(version_match,'ref',None)} deployed={file}")]
    tc = TriageCandidate(chain_id=chain_id, address=address, file=file,
                         audited_ref=(coverage.audited_refs[0] if coverage and coverage.audited_refs else None),
                         deployed_ref=getattr(version_match, "ref", None), status=TC_UNCERTAIN, deltas=deltas,
                         sources=src)
    functional = [d for d in deltas if d.change in ("added", "removed") or d.categories or
                  (d.change == "changed")]
    if not functional:
        tc.status, tc.certainty = TC_NO_FUNCTIONAL_DELTA, VERIFIED
        tc.justification = ["no functional delta (only comments/formatting/reordering)"]
        return tc

    funds = _overall_funds(deltas)
    tc.rank = _rank(deltas, mapping, verified, version_match, coverage, funds)

    stop = _stop_reasons(mapping, verified, version_match, coverage)
    if funds == NO_IDENTIFIED_FUNDS_PATH:
        stop.append("no identified user-funds path on the changed functions")
    if stop:
        tc.status, tc.certainty, tc.stop_reasons = TC_BLOCKED, VERIFIED, stop
        tc.justification = ["STOP conditions prevail over the score"] + stop
        tc.score = 0.0
        return tc

    # Not blocked. Prioritise only when the whole evidence chain is present AND coverage is known.
    chain_complete = (mapping is not None and verified is not None and version_match is not None
                      and coverage is not None)
    coverage_known = coverage is not None and coverage.status != "UNKNOWN"
    rb = tc.rank
    tc.score = round(0.30 * rb.delta_priority + 0.20 * rb.fact_certainty + 0.20 * rb.audit_coverage +
                     0.20 * rb.funds_proximity + 0.10 * rb.validation_capability, 4)
    if chain_complete and coverage_known and rb.fact_certainty >= 1.0:
        tc.status, tc.certainty = TC_PRIORITIZED, VERIFIED
        tc.justification = [f"evidence chain complete; categories={tc.categories}; funds={funds}"]
    else:
        tc.status, tc.certainty = TC_UNCERTAIN, UNKNOWN
        missing = [n for n, x in (("mapping", mapping), ("verified", verified), ("version_match", version_match),
                                  ("coverage", coverage)) if x is None]
        if not coverage_known and coverage is not None:
            missing.append("coverage=UNKNOWN")
        tc.justification = [f"kept as UNCERTAIN (missing/unknown: {missing}); score does not promote it"]
    return tc
