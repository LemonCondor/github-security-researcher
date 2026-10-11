"""M5 compatibility layer over the deterministic decision engine (analysis/decision.py).

`decide()` keeps its M5 signature and return type, but the verdict now comes exclusively from
`analysis.decision.decide` and the score from `analysis.decision.confidence_score`.
Behaviour changes vs M5 (intentional, see decision engine):
  * the LLM can no longer produce FALSE_POSITIVE on its own (former basis "llm_only");
  * the confidence score is no longer capped according to the verdict (score and verdict independent).
"""
from __future__ import annotations

from dataclasses import dataclass

from ..analysis import decision as engine
from ..analysis.evidence import assess
from .static import StepResult


@dataclass
class Verdict:
    verdict: str          # CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE
    basis: str            # static | none   ("llm_only" exists only in legacy rows)
    score: float
    quality: str          # strong_static | weak | n/a
    rationale: dict


def decide(finding: dict, steps: list[StepResult], llm: dict | None) -> Verdict:
    ev = assess(finding, steps, llm)
    d = engine.decide(ev, (llm or {}).get("verdict"), bool((llm or {}).get("injection_suspected")))
    score, trail = engine.confidence_score(float(finding.get("scanner_confidence", 0.4)), ev,
                                           (llm or {}).get("confidence"))
    basis = "static" if d.final_verdict in ("CONFIRMED", "FALSE_POSITIVE") else "none"
    llm_v = (llm or {}).get("verdict")
    llm_c = float((llm or {}).get("confidence") or 0.0)
    quality = "n/a"
    if d.final_verdict == "INCONCLUSIVE":
        has_ind_sup = any(e.supports and e.independent for e in ev.items)
        has_con = any(e.contradicts for e in ev.items if e.type != "LLM_REASONING")
        quality = "strong_static" if (has_ind_sup and not has_con and llm_v in ("confirmed", "likely")
                                      and llm_c >= 0.7) else "weak"
    rationale = {
        "summary": d.decision_reason,
        "evidence_basis": basis,
        "executed_target_code": False,
        "dynamic_proof": None,
        "quality": quality,
        "llm_verdict": llm_v,
        "llm_confidence": llm_c if llm_v else None,
        "steps": [{"validator": s.validator, "outcome": s.outcome, "signal": s.signal, "strength": s.strength}
                  for s in steps],
        "score_trail": trail,
        "requires_human_review": d.human_review_required,
        "decision": d.to_dict(),
        "evidence": [e.to_dict() for e in ev.sorted_items()],
    }
    return Verdict(d.final_verdict, basis, score, quality, rationale)
