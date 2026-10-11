"""Common finding contract shared by the non-repository engines (smart contracts, passive web).

Deliberately NOT the security `Finding` (analysis/findings.py, repository-bound, stored in `findings`, R1-R5) nor
the ordinary-bug `BugCandidate`. Engine findings are reports only: no SQLite table yet (a migration will be decided
once the engines are validated), and no engine may emit CONFIRMED.

Location is optional and typed by engine: a web finding has no repository/commit/file/line; a deployed-contract
finding carries chain/address/implementation/bytecode hash in `location`, never in file/line.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

ENGINE_STATUSES = (
    "OBSERVATION",      # technical fact (e.g. header absent): not a vulnerability by itself
    "CANDIDATE",        # pattern that may be a vulnerability: needs evidence review
    "NEEDS_REVIEW",     # ambiguous: a human must look
    "FALSE_POSITIVE",   # deterministic negative evidence
)
SEVERITIES = ("info", "low", "medium", "high", "critical")
VALIDATION_METHODS = ("pattern", "ast", "tool", "fixture-test", "manual", "none")


class DependencyMissing(RuntimeError):
    """An optional external tool is not installed: engines raise this, the CLI reports it and exits cleanly."""


@dataclass
class Evidence:
    kind: str                     # e.g. "code", "http-header", "cookie", "tool-output"
    detail: str                   # short, factual; never a secret value (redact)
    source: str = ""              # file:line, URL, fixture name, tool name
    strength: str = "weak"        # weak | moderate | strong (strong only from a deterministic proof)


@dataclass
class EngineFinding:
    engine: str                   # "contracts.solidity/1", "web.passive/1", ...
    target: str                   # path, URL or contract identifier as given by the user
    rule: str
    category: str
    severity: str                 # estimated, see SEVERITIES
    confidence: float             # prior of the rule, NOT a validated score
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    validation_method: str = "pattern"
    status: str = "CANDIDATE"
    limitations: list[str] = field(default_factory=list)   # what this result does NOT prove
    location: dict = field(default_factory=dict)            # engine-specific: {file, line, contract, function} |
                                                            # {url, header} | {chain, address, implementation, ...}
    tool: dict = field(default_factory=dict)                # {name, version} when an external tool produced it
    extra: dict = field(default_factory=dict)
    finding_id: str = ""

    def __post_init__(self):
        if self.status not in ENGINE_STATUSES:
            raise ValueError(f"invalid engine status {self.status!r} (CONFIRMED is never emitted by an engine)")
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if self.validation_method not in VALIDATION_METHODS:
            raise ValueError(f"invalid validation_method {self.validation_method!r}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.evidence = [e if isinstance(e, Evidence) else Evidence(**e) for e in self.evidence]
        if not self.finding_id:
            key = json.dumps([self.engine.split("/")[0], self.target, self.rule, self.category,
                              sorted(self.location.items())], default=str)
            self.finding_id = "e" + hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return asdict(self)
