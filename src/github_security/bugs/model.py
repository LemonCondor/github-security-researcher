"""Ordinary (non-security) bug candidates: model and deterministic status rules.

Deliberately separate from the security pipeline (findings.Finding, evidence.py, decision.py R1-R5):
a bug candidate never becomes CONFIRMED / FALSE_POSITIVE / INCONCLUSIVE and never enters `analyze_finding`.
A pattern match is never a confirmed bug: the strongest status reachable here is LIKELY_BUG, which still
needs a human and, later, a reproducing test.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

BUG_CANDIDATE = "BUG_CANDIDATE"   # pattern matched, no negative evidence, no ambiguity, not reviewed yet
LIKELY_BUG = "LIKELY_BUG"         # BUG_CANDIDATE + contextual review agrees with verifiable cited lines
NEEDS_REVIEW = "NEEDS_REVIEW"     # ambiguous pattern, or review disagrees / cannot conclude
FALSE_POSITIVE = "FALSE_POSITIVE" # deterministic negative evidence found by the detector
BUG_STATUSES = (BUG_CANDIDATE, LIKELY_BUG, NEEDS_REVIEW, FALSE_POSITIVE)

BUG_CATEGORIES = {
    "ignored-error": "result of a module function declaring an `error` result is discarded",
    "overwritten-error": "an error value is overwritten before it is read",
    "unchecked-split-index": "constant index into a split result without a length check (panic)",
    "unchecked-submatch-index": "constant index into a regexp submatch result without a match check (panic)",
    "nil-before-err-check": "a returned value is nil-checked and exits before the returned error is examined",
}


@dataclass
class BugCandidate:
    file: str
    line: int
    category: str
    rule: str
    function: str
    explanation: str              # what the pattern means
    suspicion: str                # why this precise site is suspicious
    snippet: str                  # numbered code excerpt around the site
    confidence: float             # detector prior, NOT a validated score
    related_lines: list[int] = field(default_factory=list)
    negative_evidence: list[str] = field(default_factory=list)   # facts that make the bug impossible
    ambiguity: list[str] = field(default_factory=list)           # facts that prevent a conclusion
    context: list[dict] = field(default_factory=list)            # {kind, file, start, end} for the reviewer
    status: str = ""
    status_reason: str = ""
    fingerprint: str = ""

    def __post_init__(self):
        if self.category not in BUG_CATEGORIES:
            raise ValueError(f"unknown bug category {self.category!r}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.status:
            self.status, self.status_reason = decide(self)
        if not self.fingerprint:
            code = re.sub(r"\s+", " ", self.snippet_line()).strip()
            key = "|".join([self.file, self.category, self.rule, self.function, code])
            self.fingerprint = hashlib.sha256(key.encode()).hexdigest()

    def snippet_line(self) -> str:
        m = re.search(rf"^\s*{self.line}\s\|\s?(.*)$", self.snippet, re.M)
        return m.group(1) if m else ""

    def to_dict(self) -> dict:
        return asdict(self)


def decide(c: BugCandidate, review: dict | None = None) -> tuple[str, str]:
    """Deterministic status. The review (LLM) can only move BUG_CANDIDATE to LIKELY_BUG or NEEDS_REVIEW:
    it can neither override detector facts (B1/B2) nor dismiss a candidate on its own (B4)."""
    if c.negative_evidence:
        return FALSE_POSITIVE, "B1 deterministic negative evidence: " + "; ".join(c.negative_evidence)
    if c.ambiguity:
        return NEEDS_REVIEW, "B2 ambiguous pattern: " + "; ".join(c.ambiguity)
    if review is None:
        return BUG_CANDIDATE, "B5 pattern matched, no negative evidence, not reviewed"
    if review.get("verdict") == LIKELY_BUG and review.get("lines"):
        return LIKELY_BUG, "B3 pattern + review agrees with verified lines (not confirmed: no reproducing test)"
    return NEEDS_REVIEW, f"B4 review verdict {review.get('verdict')}: the review alone cannot dismiss or conclude"
