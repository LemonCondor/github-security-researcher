"""Structured evidence assessment.

Turns the outputs of earlier stages (scanner detection, M5 static steps, M4 LLM analysis) into a flat,
typed list of Evidence items. The decision engine only ever reads these typed fields (enums/bools);
it never parses free text, so repository content cannot steer a decision.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

EVIDENCE_TYPES = ("STATIC_DATAFLOW", "SOURCE_TO_SINK", "DEPENDENCY_USAGE", "CONFIGURATION", "CODE_CONTEXT",
                  "TEST_RESULT", "NEGATIVE_EVIDENCE", "BUILD_ONLY_MODULE", "LLM_REASONING")
STRENGTHS = ("weak", "moderate", "strong")
STATUSES = ("VERIFIED",      # established locally by a deterministic, reproducible tool/check
            "UNVERIFIED",    # observed but could not be re-established
            "ADVISORY")      # opinion (LLM): never independent evidence
STRENGTH_RANK = {"weak": 1, "moderate": 2, "strong": 3}


@dataclass(frozen=True)
class Evidence:
    type: str
    source: str              # producing component, e.g. "static.secret_analysis", "scanner:semgrep", "llm:<model>"
    description: str         # human-readable; NEVER read by the decision engine
    strength: str
    supports: bool           # supports "this is a real vulnerability"
    contradicts: bool        # supports "this is not a vulnerability here"
    reproducible: bool
    status: str
    data: dict = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self):
        if self.type not in EVIDENCE_TYPES:
            raise ValueError(f"evidence type {self.type!r}")
        if self.strength not in STRENGTHS:
            raise ValueError(f"strength {self.strength!r}")
        if self.status not in STATUSES:
            raise ValueError(f"status {self.status!r}")
        if self.supports and self.contradicts:
            raise ValueError("an evidence item cannot both support and contradict")
        if self.type == "LLM_REASONING" and self.status != "ADVISORY":
            raise ValueError("LLM_REASONING is always ADVISORY")

    @property
    def independent(self) -> bool:
        """Independent = verified by a deterministic local check, not an opinion."""
        return self.type != "LLM_REASONING" and self.status == "VERIFIED"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidenceAssessment:
    finding_id: str
    category: str
    items: list[Evidence]

    def sorted_items(self) -> list[Evidence]:
        return sorted(self.items, key=lambda e: (e.type, e.source, e.strength, e.supports, e.contradicts))


# --------------------------------------------------------------------------- builders

_CODE_CATEGORIES = {"sql-injection", "command-injection", "code-injection", "path-traversal", "ssrf", "xss",
                    "auth-bypass", "insecure-deserialization", "weak-crypto", "other"}


def from_detection(finding: dict) -> list[Evidence]:
    """The scanner hit itself, as unverified evidence (verification comes from rule reproduction)."""
    if finding.get("category") in _CODE_CATEGORIES and finding.get("source") and finding.get("sink"):
        return [Evidence("STATIC_DATAFLOW", f"scanner:{finding.get('scanner')}",
                         f"taint rule {finding.get('rule')} reports {finding.get('source')} -> {finding.get('sink')}",
                         "weak", True, False, False, "UNVERIFIED")]
    return []


def from_static_step(step, finding: dict) -> list[Evidence]:
    """Map an M5 StepResult to typed evidence. Pure function of the step's structured fields."""
    v, sig, st = step.validator, step.signal, step.strength
    sup, con = sig == "supports_real", sig == "supports_false_positive"
    data = dict(step.data or {})
    if v == "static.rule_reproduction":
        if sup:
            etype = "STATIC_DATAFLOW" if finding.get("source") and finding.get("sink") else "CODE_CONTEXT"
            return [Evidence(etype, v, step.details, "moderate" if etype == "STATIC_DATAFLOW" else "weak",
                             True, False, True, "VERIFIED", data)]
        if con:
            return [Evidence("NEGATIVE_EVIDENCE", v, step.details, "weak", False, True, True, "VERIFIED", data)]
        return []      # tool unavailable / error: no evidence either way
    if v == "static.non_production_path":
        if step.outcome == "FALSE_POSITIVE" and con:
            return [Evidence("CODE_CONTEXT", v, step.details, "strong", False, True, True, "VERIFIED", data)]
        return []
    if v == "static.secret_analysis":
        if step.outcome == "CONFIRMED":
            return [Evidence("CONFIGURATION", v, step.details, "strong", True, False, True, "VERIFIED", data)]
        if con:
            etype = "NEGATIVE_EVIDENCE"
            return [Evidence(etype, v, step.details, "strong" if st == "strong" else "weak",
                             False, True, True, "VERIFIED", data)]
        if sup:
            return [Evidence("CONFIGURATION", v, step.details, "moderate" if st == "strong" else "weak",
                             True, False, True, "VERIFIED", data)]
        return []
    if v == "static.dependency_usage":
        if sup or con:
            # Import of a package != reachability of the vulnerable function: never above moderate.
            # Only a real import by product code is moderate; tooling pins / transitive compilation are weak.
            weak_support = data.get("relation") in ("tooling_pin", "transitive_compiled")
            return [Evidence("DEPENDENCY_USAGE", v, step.details,
                             "moderate" if sup and not weak_support else "weak",
                             sup, con, True, "VERIFIED", data)]
        return []
    if v == "static.go_dataflow":
        # A resolved syntactic path is real support but never a proof: capped at moderate, so the
        # engine's CONFIRMED criteria (SOURCE_TO_SINK >= strong) can never be met by it alone.
        if sup:
            return [Evidence("SOURCE_TO_SINK", v, step.details, "moderate", True, False, True, "VERIFIED", data)]
        if con:
            return [Evidence("NEGATIVE_EVIDENCE", v, step.details, "weak", False, True, True, "VERIFIED", data)]
        return []
    if v == "static.build_only_module":
        if step.outcome == "FALSE_POSITIVE" and con and st == "strong":
            return [Evidence("BUILD_ONLY_MODULE", v, step.details, "strong", False, True, True, "VERIFIED", data)]
        return []
    # unknown validator: keep it, but only as weak verified context
    if sup or con:
        return [Evidence("CODE_CONTEXT", v, step.details, "weak", sup, con, True, "VERIFIED", data)]
    return []


def from_llm(llm: dict | None, model: str | None = None) -> list[Evidence]:
    """LLM analysis is always ADVISORY LLM_REASONING, weak, non-reproducible."""
    if not llm:
        return []
    verdict = llm.get("verdict")
    sup = verdict in ("confirmed", "likely")
    con = verdict == "false_positive"
    data = {"verdict": verdict, "confidence": llm.get("confidence"),
            "injection_suspected": bool(llm.get("injection_suspected")),
            "cited_lines": [(e.get("file"), e.get("line")) for e in (llm.get("evidence") or [])]}
    return [Evidence("LLM_REASONING", f"llm:{model or llm.get('_model') or 'claude'}",
                     str(llm.get("reasoning_summary") or "")[:2000], "weak", sup, con, False, "ADVISORY", data)]


def assess(finding: dict, steps: list, llm: dict | None, model: str | None = None) -> EvidenceAssessment:
    items: list[Evidence] = []
    reproducers = ("static.rule_reproduction", "static.go_dataflow") if finding.get("scanner") == "go_dataflow" \
        else ("static.rule_reproduction",)
    reproduced = any(getattr(s, "validator", "") in reproducers and s.signal == "supports_real" for s in steps)
    if not reproduced:                      # unverified detection only matters if not re-established
        items += from_detection(finding)
    for s in steps:
        items += from_static_step(s, finding)
    items += from_llm(llm, model)
    return EvidenceAssessment(finding_id=str(finding.get("id")), category=str(finding.get("category")), items=items)
