"""Normalized finding model shared by every scanner."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("DETECTED", "ANALYZED", "EVIDENCE_ASSESSED", "CONFIRMED", "FALSE_POSITIVE", "INCONCLUSIVE",
            "READY_FOR_HUMAN_REVIEW")   # internal states; final verdicts are only the 3 middle ones

# Normalized vulnerability classes (subset of CWE we care about first).
CATEGORIES = {
    "sql-injection": "CWE-89",
    "command-injection": "CWE-78",
    "code-injection": "CWE-94",
    "path-traversal": "CWE-22",
    "ssrf": "CWE-918",
    "xss": "CWE-79",
    "auth-bypass": "CWE-287",
    "insecure-deserialization": "CWE-502",
    "secret": "CWE-798",
    "vulnerable-dependency": "CWE-1395",
    "weak-crypto": "CWE-327",
    "other": None,
}

# Additional CWEs that belong to an existing category (CATEGORIES keeps one canonical CWE each).
CWE_ALIASES = {
    "CWE-328": "weak-crypto",       # use of weak hash (e.g. MD5/SHA1)
}


@dataclass
class Finding:
    repository: str
    commit: str
    file: str
    line: int
    rule: str
    category: str
    severity: str
    confidence: float          # scanner prior, NOT a validated score
    scanner: str
    description: str
    evidence: str = ""
    end_line: int | None = None
    source: str | None = None
    sink: str | None = None
    references: list[str] = field(default_factory=list)
    status: str = "DETECTED"
    extra: dict = field(default_factory=dict)   # structured scanner data; NOT part of the fingerprint
    id: str = ""
    fingerprint: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.category not in CATEGORIES:
            self.category = "other"
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.fingerprint:
            self.fingerprint = fingerprint(self)
        if not self.id:
            self.id = self.fingerprint[:12]

    def to_dict(self) -> dict:
        return asdict(self)


def _norm_code(snippet: str) -> str:
    return re.sub(r"\s+", " ", snippet or "").strip()


def fingerprint(f: Finding) -> str:
    """Stable across commits: does not include line numbers or commit sha,
    so a finding that merely moves is recognised as the same one."""
    key = "|".join([f.repository.lower(), f.file, f.category, f.rule, _norm_code(f.evidence)])
    return hashlib.sha256(key.encode()).hexdigest()
