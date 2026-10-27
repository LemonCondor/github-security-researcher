"""Data types of `gsr hunt` (agentic logic-bug hunting). Verdicts are always decided by code, never by the model."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

STATUSES = ("GATED", "NO_FINDINGS", "ERROR", "REJECTED_NO_REPRO", "DUPLICATE", "REJECTED_FIX", "DROPPED_SKEPTIC", "READY")


@dataclass
class Target:
    path: str
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class Finding:
    file: str
    function: str
    hypothesis: str
    realistic_input: str
    expected: str
    actual: str
    repro_path: str
    user_impact: str
    confidence: float


@dataclass
class Result:
    status: str
    target: str = ""
    finding: Finding | None = None
    detail: str = ""
    branch: str | None = None
    commit: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
