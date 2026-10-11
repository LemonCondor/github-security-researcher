"""Glue between scanners, storage and the review/validation stages."""
from __future__ import annotations

import json
import time

from .observability import event
from .scanner.base import Scanner, ScanTarget
from .scanner.runner import run_scan
from .storage.database import Database


def scan_and_store(db: Database, target: ScanTarget, scanners: list[Scanner], mode: str = "full") -> dict:
    scan_id = db.start_scan(target.slug, target.commit, mode, str(target.path))
    t0 = time.monotonic()
    try:
        res = run_scan(target, scanners)
    except Exception as e:
        db.fail_scan(scan_id, str(e))
        raise
    ms = int((time.monotonic() - t0) * 1000)
    stats = db.record_scan(scan_id, res.findings, res.scanners_run, res.scanners_skipped, ms)
    event("scan", "scan.recorded", scan_id=scan_id, repository=target.slug, commit=target.commit,
          duration_ms=ms, **stats)
    return {"scan_id": scan_id, "repository": target.slug, "commit": target.commit, "duration_ms": ms,
            "scanners_run": res.scanners_run, "scanners_skipped": res.scanners_skipped, **stats}


def _decision_layers(db: Database, fp: str) -> dict:
    d = db.latest_decision(fp)
    if d is None:
        return {"evidence": [], "confidence_score": None, "proposed_verdict": None, "final_verdict": None,
                "decision_reason": None, "human_review_required": None}
    reason = json.loads(d["decision_reason"])
    return {
        "evidence": [{k: (bool(r[k]) if k in ("supports", "contradicts", "reproducible", "independent") else r[k])
                      for k in ("type", "source", "description", "strength", "supports", "contradicts",
                                "reproducible", "status", "independent")} for r in db.evidence_for(fp)],
        "confidence_score": d["confidence_score"],
        "score_trail": json.loads(d["score_trail"]),
        "proposed_verdict": d["proposed_verdict"],
        "final_verdict": d["final_verdict"],
        "decision_reason": {
            "verdict": d["final_verdict"], "rule": d["rule"], "summary": reason["decision_reason"],
            "rules_applied": reason["rules_applied"], "supporting_evidence": reason["supporting_evidence"],
            "contradicting_evidence": reason["contradicting_evidence"],
            "missing_evidence": reason["missing_evidence"],
            "human_review_required": bool(d["human_review_required"]),
            "human_review_reasons": reason["human_review_reasons"],
            "confidence_score": d["confidence_score"], "engine_version": d["engine_version"],
            "executed_target_code": reason.get("executed_target_code", False)},
        "human_review_required": bool(d["human_review_required"]),
    }


def finding_report(db: Database, ident: str) -> dict | None:
    """All four layers, kept separate: detection / llm_review / validation / verdict."""
    f = db.get_finding(ident)
    if f is None:
        return None
    fp = f["fingerprint"]
    llm = db.latest_llm_review(fp)
    v = db.latest_verdict(fp)
    occ = db.conn.execute(
        "SELECT o.scan_id, c.sha, o.file, o.line FROM occurrences o JOIN commits c ON c.id=o.commit_id "
        "WHERE o.finding_fp=? ORDER BY o.rowid", (fp,)).fetchall()
    return {
        "id": f["id"], "fingerprint": fp, "repository": f["repository"], "state": f["state"],
        "status": f["status"],
        "detection": {
            "scanner": f["scanner"], "rule": f["rule"], "category": f["category"],
            "severity": f["severity"], "scanner_confidence": f["scanner_confidence"],
            "commit": f["last_commit"], "file": f["file"], "line": f["line"], "end_line": f["end_line"],
            "source": f["source"], "sink": f["sink"], "description": f["description"],
            "evidence": f["evidence"], "references": json.loads(f["refs"]),
            "occurrences": [dict(o) for o in occ],
        },
        "llm_review": None if llm is None else {
            "model": llm["model"], "created_at": llm["created_at"], "context_sha256": llm["context_sha256"],
            **json.loads(llm["output_json"])},
        "static_validation": [{**dict(r), "data": json.loads(r["data"])} for r in db.validations_for(fp, True)],
        "regression_drafts": [{"path": d["path"], "status": d["status"], "note": "never executed, not evidence"}
                              for d in db.regression_drafts_for(fp)],
        "contextual_analysis": None if llm is None else json.loads(llm["output_json"]),
        **_decision_layers(db, fp),
        "verdict": None if v is None else {
            "verdict": v["verdict"], "basis": v["basis"], "confidence_score": v["confidence_score"],
            "executed_target_code": json.loads(v["rationale"]).get("executed_target_code", False),
            "rationale": json.loads(v["rationale"]), "decided_by": v["decided_by"], "at": v["created_at"],
            "source": v["source"]},
    }


def ensure_advisory(db: Database, finding: dict, get=None) -> dict:
    """Make sure a dependency finding carries its OSV advisory (backfill for findings stored before it existed)."""
    import re

    from .scanner.dependencies import fetch_advisory
    extra = json.loads(finding.get("extra") or "{}") if isinstance(finding.get("extra"), str) else (finding.get("extra") or {})
    if extra.get("advisory"):
        return extra
    m = re.match(r"([^:]+):(.+)==(.+)$", finding.get("evidence") or "")
    if not m:
        return extra
    try:
        extra["advisory"] = fetch_advisory(finding["rule"], m.group(1), m.group(2), m.group(3), get=get)
    except OSError as e:
        event("analysis", "advisory.fetch_failed", finding_id=finding.get("id"), error=str(e))
        return extra
    db.conn.execute("UPDATE findings SET extra=? WHERE fingerprint=?", (json.dumps(extra), finding["fingerprint"]))
    return extra


def review_finding(db: Database, ident: str, runner=None, model: str | None = None) -> dict:
    """M4: contextual LLM review of one stored finding. Advisory layer only."""
    from pathlib import Path

    from .ai import reviewer
    from .analysis.context import build_context

    f = db.get_finding(ident)
    if f is None:
        raise KeyError(ident)
    fp = f["fingerprint"]
    workdir = db.workdir_for(fp)
    if not workdir or not Path(workdir).is_dir():
        raise FileNotFoundError(f"checkout for {f['repository']} not available; rescan first")
    finding = dict(f)
    if finding["category"] == "vulnerable-dependency":
        finding["extra"] = ensure_advisory(db, finding)
    ctx = build_context(Path(workdir), finding)
    try:
        rv = reviewer.review(ctx, runner or reviewer.claude_cli_runner, model=model)
    except reviewer.ReviewError as e:
        db.add_llm_review(fp, f["last_commit_id"], model=model, context_sha256=ctx.sha256(),
                          output={"verdict": "unknown", "confidence": 0.0}, duration_ms=0, error=str(e))
        event("analysis", "llm_review.error", finding_id=f["id"], repository=f["repository"], error=str(e))
        raise
    db.add_llm_review(fp, f["last_commit_id"], model=rv.model, context_sha256=rv.context_sha256,
                      output=rv.output, duration_ms=rv.duration_ms)
    db.set_status(fp, "ANALYZED")
    event("analysis", "llm_review.done", finding_id=f["id"], repository=f["repository"],
          verdict=rv.output["verdict"], confidence=rv.output["confidence"], duration_ms=rv.duration_ms,
          warnings=rv.warnings, injection_suspected=rv.output["injection_suspected"])
    return {"id": f["id"], **rv.output}


def validate_finding(db: Database, ident: str, scanners: list[Scanner], evidence_root,
                     triage: bool = False) -> dict:
    """CANDIDATE -> CONTEXTUAL_ANALYSIS (stored LLM review, if any) -> EVIDENCE_ASSESSMENT -> DECISION_ENGINE.

    Static only: never executes repository code. The verdict comes from the deterministic engine;
    the LLM review is one ADVISORY evidence item and the confidence score is computed separately.
    """
    import uuid
    from pathlib import Path

    from .analysis import decision as engine
    from .analysis.evidence import assess
    from .validation.static import run_static_steps

    f = db.get_finding(ident)
    if f is None:
        raise KeyError(ident)
    fp = f["fingerprint"]
    workdir = db.workdir_for(fp)
    if not workdir or not Path(workdir).is_dir():
        raise FileNotFoundError(f"checkout for {f['repository']} not available; rescan first")
    finding = dict(f)
    run_id = uuid.uuid4().hex[:12]
    t0 = time.monotonic()

    # evidence collection (static, local)
    steps = run_static_steps(Path(workdir), finding, {s.name: s for s in scanners})
    llm_row = db.latest_llm_review(fp)
    llm = json.loads(llm_row["output_json"]) if llm_row else None
    assessment = assess(finding, steps, llm, llm_row["model"] if llm_row else None)
    if triage:
        d0 = engine.decide(assessment, None, False)
        if d0.rule not in engine.LLM_INVARIANT_DECISIVE_RULES:
            # not statically decidable: persist nothing, the finding continues to CONTEXTUAL_ANALYSIS
            return {"id": f["id"], "decisive": False, "rule": d0.rule}
    for s in steps:
        db.add_validation(fp, f["last_commit_id"], run_id=run_id, validator=s.validator, outcome=s.outcome,
                          signal=s.signal, strength=s.strength, details=s.details, data=s.data,
                          duration_ms=s.duration_ms)
    db.add_evidence(fp, run_id, assessment.sorted_items())
    db.set_status(fp, "EVIDENCE_ASSESSED")

    # decision (deterministic) and score (separate)
    d = engine.decide(assessment, (llm or {}).get("verdict"), bool((llm or {}).get("injection_suspected")))
    score, trail = engine.confidence_score(float(finding["scanner_confidence"]), assessment,
                                           (llm or {}).get("confidence"))
    basis = "static" if d.final_verdict in ("CONFIRMED", "FALSE_POSITIVE") else "none"
    extra = {"evidence_basis": basis, "executed_target_code": False, "dynamic_proof": None,
             "contextual_analysis": ("skipped: statically decided by " + d.rule +
                                     " (LLM output cannot change this rule's outcome)") if triage
             else ("llm review used" if llm else "no llm review")}

    ev_dir = Path(evidence_root) / f["id"] / run_id
    ev_dir.mkdir(parents=True, exist_ok=True)
    bundle = {
        "finding_id": f["id"], "fingerprint": fp, "repository": f["repository"], "commit": f["last_commit"],
        "pipeline": ["DETECTED", "CONTEXTUAL_ANALYSIS(skipped: statically decided)" if triage
                     else ("ANALYZED" if llm else "ANALYZED(skipped: no LLM review)"),
                     "EVIDENCE_ASSESSED", d.final_verdict] +
                    (["READY_FOR_HUMAN_REVIEW"] if d.human_review_required else []),
        "detection": {k: finding[k] for k in ("scanner", "rule", "category", "severity", "scanner_confidence",
                                              "file", "line", "end_line", "evidence")},
        "contextual_analysis": llm,
        "static_steps": [s.__dict__ for s in steps],
        "evidence": [e.to_dict() for e in assessment.sorted_items()],
        "confidence_score": score,
        "score_trail": trail,
        "proposed_verdict": d.proposed_verdict,
        "final_verdict": d.final_verdict,
        "decision": {**d.to_dict(), **extra},
        "disclaimer": "Static analysis only. No target code was executed. Not confirmed by execution.",
    }
    (ev_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, default=str))
    db.conn.execute("UPDATE validations SET evidence_dir=? WHERE run_id=?", (str(ev_dir), run_id))
    db.add_decision(fp, run_id, d, score, trail, extra)
    ms = int((time.monotonic() - t0) * 1000)
    event("decision", "decision.made", finding_id=f["id"], repository=f["repository"], verdict=d.final_verdict,
          rule=d.rule, proposed=d.proposed_verdict, score=score, human_review=d.human_review_required,
          evidence=len(assessment.items), duration_ms=ms)

    supports_ind = any(e.supports and e.independent for e in assessment.items)
    contra = any(e.contradicts and e.type != "LLM_REASONING" for e in assessment.items)
    quality = "n/a"
    if d.final_verdict == "INCONCLUSIVE":
        quality = "strong_static" if (supports_ind and not contra and (llm or {}).get("verdict") in
                                      ("confirmed", "likely") and float((llm or {}).get("confidence") or 0) >= 0.7) \
            else "weak"
    return {"id": f["id"], "decisive": True, "llm_skipped": triage,
            "verdict": d.final_verdict, "basis": basis, "confidence_score": score,
            "quality": quality, "rule": d.rule, "proposed_verdict": d.proposed_verdict,
            "human_review_required": d.human_review_required,
            "steps": [(s.validator, s.outcome, s.signal, s.strength) for s in steps],
            "evidence": str(ev_dir / "bundle.json")}


def draft_regression_test(db: Database, ident: str, evidence_root, runner=None, model: str | None = None) -> dict:
    """LLM regression-test DRAFT. Status UNEXECUTED; never run, never evidence."""
    from pathlib import Path

    from .ai import reviewer
    from .ai.regression_draft import write_draft
    from .analysis.context import build_context

    f = db.get_finding(ident)
    if f is None:
        raise KeyError(ident)
    workdir = db.workdir_for(f["fingerprint"])
    if not workdir or not Path(workdir).is_dir():
        raise FileNotFoundError("checkout not available; rescan first")
    ctx = build_context(Path(workdir), dict(f))
    path, meta = write_draft(ctx, dict(f), Path(evidence_root) / f["id"] / "drafts",
                             runner or reviewer.claude_cli_runner, model)
    db.add_regression_draft(f["fingerprint"], model=meta["model"], path=str(path), output=meta)
    event("validation", "regression_draft.written", finding_id=f["id"], status="UNEXECUTED")
    return {"id": f["id"], "status": "UNEXECUTED", "path": str(path), **meta}


def analyze_finding(db: Database, ident: str, scanners: list[Scanner], evidence_root, runner=None,
                    model: str | None = None) -> dict:
    """Full per-finding pipeline with pre-LLM triage.

    CANDIDATE -> [triage: static evidence + engine without LLM]
       decided by an LLM-invariant rule (R2/R3) -> decision recorded, LLM NOT called
       otherwise -> CONTEXTUAL_ANALYSIS (LLM) -> EVIDENCE_ASSESSMENT -> DECISION_ENGINE
    """
    pre = validate_finding(db, ident, scanners, evidence_root, triage=True)
    if pre["decisive"]:
        event("analysis", "llm.skipped", finding_id=pre["id"], rule=pre["rule"], verdict=pre["verdict"])
        return pre
    review_finding(db, ident, runner=runner, model=model)
    return validate_finding(db, ident, scanners, evidence_root)


# --------------------------------------------------------------------------- ordinary bugs (separate pipeline)

def detect_and_store_bugs(db: Database, target: ScanTarget) -> dict:
    """Ordinary bug candidates for one checkout -> bug_* tables. Never touches findings / decisions (R1-R5).
    Static only (tree-sitter parse of local .go files); nothing is executed."""
    from .bugs.go_detectors import detect_go_report
    from .bugs.storage import BugStore

    store = BugStore(db)
    scan_id = store.start_scan(target.slug, target.commit, str(target.path))
    t0 = time.monotonic()
    try:
        report = detect_go_report(target.path)
    except Exception as e:
        store.fail_scan(scan_id, str(e))
        raise
    ms = int((time.monotonic() - t0) * 1000)
    stats = store.record(scan_id, report.candidates, ms, report)
    event("scan", "bugs.recorded", repository=target.slug, commit=target.commit, duration_ms=ms,
          candidates=stats["candidates"], dedup=stats["dedup"], gone_reasons=stats["gone_reasons"])
    return {"repository": target.slug, "commit": target.commit, "duration_ms": ms, **stats}


def scan_repository(db: Database, target: ScanTarget, scanners: list[Scanner], bugs: bool = True) -> dict:
    """One checkout -> {"security": <findings summary>, "bugs": <bug candidates summary>}.
    Two separate stores and models: security findings keep their R1-R5 pipeline, bug candidates their own."""
    out = {"security": scan_and_store(db, target, scanners)}
    out["bugs"] = detect_and_store_bugs(db, target) if bugs else None
    return out


def review_bug(db: Database, ident: str, runner=None, model: str | None = None) -> dict:
    """Contextual LLM review of one stored bug candidate (advisory; status still decided by bugs.model.decide)."""
    from pathlib import Path

    from .bugs.review import review_candidate
    from .bugs.storage import BugStore

    store = BugStore(db)
    row = store.get(ident)
    if row is None:
        raise KeyError(ident)
    workdir = store.workdir_for(row["fingerprint"])
    if not workdir or not Path(workdir).is_dir():
        raise FileNotFoundError(f"checkout for {row['repository']} not available; rescan first")
    c = store.candidate_from_row(row)
    rec = review_candidate(Path(workdir), c, runner=runner, model=model)
    store.add_review(row["fingerprint"], rec)
    event("analysis", "bug_review.done", bug_id=row["id"], status=rec["status"], duration_ms=rec["duration_ms"])
    return {"id": row["id"], **rec}
