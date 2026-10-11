"""Deterministic ternary decision engine.

Inputs : EvidenceAssessment (typed evidence) + the LLM's *proposed* verdict (recorded, never decisive).
Outputs: exactly one of CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE, plus a machine-readable reason.

The engine reads only enums/booleans of Evidence items. It never reads descriptions, code, or any
free text, so content from the analysed repository cannot influence it.
The confidence score is computed by a separate function and is never consulted by `decide`.

Rules (evaluated in order, first match wins):
  R1_CONTRADICTORY_EVIDENCE  independent evidence of moderate+ strength exists on BOTH sides
                             -> INCONCLUSIVE
  R2_SAFE_CONTEXT            independent STRONG contradicting evidence (and no moderate+ independent
                             support) -> FALSE_POSITIVE
  R3_PROOF_CRITERIA_MET      the category's minimum proof criteria are met by independent evidence
                             and no independent contradicting evidence of any strength exists
                             -> CONFIRMED
  R4_LLM_CLAIM_WITHOUT_PROOF the LLM proposes CONFIRMED or FALSE_POSITIVE but no independent evidence
                             decides it -> INCONCLUSIVE
  R5_INSUFFICIENT_EVIDENCE   default -> INCONCLUSIVE
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from .evidence import STRENGTH_RANK, Evidence, EvidenceAssessment

ENGINE_VERSION = "decision-engine/1"
# Rules that read independent evidence only. LLM evidence is never independent, so a decision reached
# by one of these rules cannot be changed by any LLM output: calling the LLM first would add nothing
# to the verdict (proved exhaustively in tests). Used by the pre-LLM triage.
LLM_INVARIANT_DECISIVE_RULES = ("R2_SAFE_CONTEXT", "R3_PROOF_CRITERIA_MET")
FINAL_VERDICTS = ("CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE")

# Minimum proof per category: any ONE of the listed (evidence type, minimum strength) pairs,
# satisfied by an INDEPENDENT (verified, non-LLM) supporting evidence item.
# LLM_REASONING never appears here. STATIC_DATAFLOW is deliberately absent for code categories:
# a reproduced taint match is a strong hint, not a proof of exploitability.
_CODE = (("SOURCE_TO_SINK", "strong"), ("TEST_RESULT", "strong"))
PROOF_CRITERIA: dict[str, tuple[tuple[str, str], ...]] = {
    "secret": (("CONFIGURATION", "strong"),),
    "vulnerable-dependency": (("DEPENDENCY_USAGE", "strong"), ("TEST_RESULT", "strong")),
    **{c: _CODE for c in ("sql-injection", "command-injection", "code-injection", "path-traversal", "ssrf",
                          "xss", "auth-bypass", "insecure-deserialization", "weak-crypto", "other")},
}


def _at_least(e: Evidence, strength: str) -> bool:
    return STRENGTH_RANK[e.strength] >= STRENGTH_RANK[strength]


def proposed_from_llm(llm_verdict: str | None) -> str | None:
    return {"confirmed": "CONFIRMED", "false_positive": "FALSE_POSITIVE",
            "likely": "INCONCLUSIVE", "unknown": "INCONCLUSIVE"}.get(llm_verdict or "")


@dataclass
class Decision:
    final_verdict: str
    proposed_verdict: str | None          # LLM proposal, ternary-mapped; advisory
    rule: str
    rules_applied: list[dict]             # every rule evaluated with its outcome
    supporting_evidence: list[dict]
    contradicting_evidence: list[dict]
    missing_evidence: list[str]
    human_review_required: bool
    human_review_reasons: list[str]
    decision_reason: str
    engine_version: str = ENGINE_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    def digest(self) -> str:
        """Stable hash of the decision content (for determinism checks)."""
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True).encode()).hexdigest()


def _ref(e: Evidence) -> dict:
    return {"type": e.type, "source": e.source, "strength": e.strength, "status": e.status,
            "independent": e.independent, "reproducible": e.reproducible}


def decide(assessment: EvidenceAssessment, llm_verdict: str | None = None,
           llm_injection_suspected: bool = False) -> Decision:
    items = assessment.sorted_items()
    ind = [e for e in items if e.independent]
    sup_ind = [e for e in ind if e.supports]
    con_ind = [e for e in ind if e.contradicts]
    llm_items = [e for e in items if e.type == "LLM_REASONING"]
    proposed = proposed_from_llm(llm_verdict)
    criteria = PROOF_CRITERIA.get(assessment.category, _CODE)

    met = [e for e in sup_ind if any(e.type == t and _at_least(e, s) for t, s in criteria)]
    trace: list[dict] = []
    verdict = rule = None

    def check(rule_id: str, cond: bool, outcome: str, why: str):
        nonlocal verdict, rule
        trace.append({"rule": rule_id, "matched": bool(cond and verdict is None), "outcome": outcome, "why": why})
        if cond and verdict is None:
            verdict, rule = outcome, rule_id

    strong_sup = [e for e in sup_ind if _at_least(e, "moderate")]
    strong_con = [e for e in con_ind if _at_least(e, "moderate")]
    check("R1_CONTRADICTORY_EVIDENCE", bool(strong_sup and strong_con), "INCONCLUSIVE",
          f"{len(strong_sup)} independent supporting vs {len(strong_con)} independent contradicting (moderate+)")
    check("R2_SAFE_CONTEXT", any(_at_least(e, "strong") for e in con_ind) and not strong_sup, "FALSE_POSITIVE",
          "independent strong evidence that the code is not vulnerable in this context")
    check("R3_PROOF_CRITERIA_MET", bool(met) and not con_ind, "CONFIRMED",
          f"criteria for {assessment.category}: any of {[f'{t}>={s}' for t, s in criteria]}")
    check("R4_LLM_CLAIM_WITHOUT_PROOF", proposed in ("CONFIRMED", "FALSE_POSITIVE"), "INCONCLUSIVE",
          f"LLM proposes {proposed}; LLM_REASONING is advisory and cannot decide alone")
    check("R5_INSUFFICIENT_EVIDENCE", True, "INCONCLUSIVE", "no rule above established a verdict")

    # What would be needed to leave INCONCLUSIVE (empty for a decided finding).
    missing: list[str] = []
    if verdict == "INCONCLUSIVE":
        if not met:
            missing.append("to CONFIRM: independent evidence meeting proof criteria: " +
                           " or ".join(f"{t} (>= {s})" for t, s in criteria))
        if con_ind:
            missing.append("to CONFIRM: resolution of contradicting independent evidence")
        if not any(_at_least(e, "strong") for e in con_ind):
            missing.append("to mark FALSE_POSITIVE: independent strong evidence of a safe context")
        elif strong_sup:
            missing.append("to mark FALSE_POSITIVE: resolution of contradicting independent support")

    reasons: list[str] = []
    if verdict == "INCONCLUSIVE":
        reasons.append("inconclusive findings always go to human review")
    if verdict == "CONFIRMED":
        reasons.append("confirmed findings are prepared for a human-submitted private report; nothing is sent")
    if proposed and verdict != proposed and not (proposed == "INCONCLUSIVE"):
        reasons.append(f"LLM proposed {proposed} but engine decided {verdict}")
    if llm_injection_suspected:
        reasons.append("possible prompt injection detected in repository content")

    summary = {
        "R1_CONTRADICTORY_EVIDENCE": "independent evidence contradicts itself",
        "R2_SAFE_CONTEXT": "independent strong evidence shows the code is not vulnerable here",
        "R3_PROOF_CRITERIA_MET": "independent evidence meets the minimum proof criteria; none contradicts it",
        "R4_LLM_CLAIM_WITHOUT_PROOF": "only the LLM takes a position; no independent evidence decides",
        "R5_INSUFFICIENT_EVIDENCE": "plausible but evidence is insufficient",
    }[rule]
    return Decision(
        final_verdict=verdict, proposed_verdict=proposed, rule=rule, rules_applied=trace,
        supporting_evidence=[_ref(e) for e in items if e.supports],
        contradicting_evidence=[_ref(e) for e in items if e.contradicts],
        missing_evidence=missing, human_review_required=bool(reasons), human_review_reasons=reasons,
        decision_reason=summary,
    )


# --------------------------------------------------------------------------- confidence score (separate)

_DELTA = {("supports", "strong"): 0.25, ("supports", "moderate"): 0.12, ("supports", "weak"): 0.04,
          ("contradicts", "strong"): -0.45, ("contradicts", "moderate"): -0.2, ("contradicts", "weak"): -0.1}


def confidence_score(scanner_confidence: float, assessment: EvidenceAssessment,
                     llm_confidence: float | None = None) -> tuple[float, list[str]]:
    """Estimated probability that the finding is a real vulnerability.

    Independent of the verdict: it is never read by `decide`, and `decide` is never read here.
    """
    score = float(scanner_confidence)
    trail = [f"scanner prior {score:.2f}"]
    for e in assessment.sorted_items():
        side = "supports" if e.supports else "contradicts" if e.contradicts else None
        if not side:
            continue
        d = _DELTA[(side, e.strength)]
        if e.type == "LLM_REASONING":
            d = (0.2 if e.supports else -0.3) * float(llm_confidence or 0.0)
        score += d
        trail.append(f"{e.type}/{e.source}/{e.strength} {'+' if d >= 0 else ''}{d:.2f}")
    score = round(max(0.01, min(0.99, score)), 3)
    trail.append(f"=> {score:.2f}")
    return score, trail
