"""Run all available scanners on a target and normalise/deduplicate the output."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from ..analysis.findings import Finding, fingerprint
from ..observability import event, timed
from .base import Scanner, ScannerError, ScanTarget
from .dependencies import OSVDependencyScanner
from .gitleaks import GitleaksScanner
from .go_dataflow import GoDataflowScanner
from .semgrep import INTERNAL_RULES, SemgrepScanner

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    scanners_skipped: dict[str, str] = field(default_factory=dict)


def default_scanners(semgrep_configs: list[str] | None = None, enabled: list[str] | None = None) -> list[Scanner]:
    all_ = [SemgrepScanner(semgrep_configs or [str(INTERNAL_RULES)]), GitleaksScanner(),
            OSVDependencyScanner(), GoDataflowScanner()]
    return [s for s in all_ if enabled is None or s.name in enabled]


def assign_occurrence_fingerprints(findings: list[Finding]) -> None:
    """Base fingerprint = repo|file|category|rule|normalised code (no line/commit).
    Identical code on *different* lines of the same file gets an ordinal suffix so the two
    issues stay distinct; several matches on the *same* line keep one fingerprint (merged)."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(fingerprint(f), []).append(f)
    for base, items in groups.items():
        lines = sorted({f.line for f in items})
        for f in items:
            k = lines.index(f.line)
            f.fingerprint = base if k == 0 else hashlib.sha256(f"{base}#{k}".encode()).hexdigest()
            f.id = f.fingerprint[:12]


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Same fingerprint => one finding; keep the highest severity/confidence, merge refs."""
    assign_occurrence_fingerprints(findings)
    by_fp: dict[str, Finding] = {}
    for f in findings:
        cur = by_fp.get(f.fingerprint)
        if cur is None:
            by_fp[f.fingerprint] = f
            continue
        if (_SEV_RANK[f.severity], f.confidence) > (_SEV_RANK[cur.severity], cur.confidence):
            f.references = list(dict.fromkeys(f.references + cur.references))
            by_fp[f.fingerprint] = f
        else:
            cur.references = list(dict.fromkeys(cur.references + f.references))
    return sorted(by_fp.values(), key=lambda f: (-_SEV_RANK[f.severity], -f.confidence, f.file, f.line))


def run_scan(target: ScanTarget, scanners: list[Scanner]) -> ScanResult:
    res = ScanResult(target=target)
    raw: list[Finding] = []
    for s in scanners:
        if not s.available():
            res.scanners_skipped[s.name] = "not installed"
            continue
        try:
            with timed("scan", f"scanner.{s.name}", repository=target.slug, commit=target.commit):
                out = s.scan(target)
            raw += out
            res.scanners_run.append(s.name)
            event("scan", "scanner.results", scanner=s.name, repository=target.slug, count=len(out))
        except ScannerError as e:
            res.scanners_skipped[s.name] = str(e)
    res.findings = dedupe(raw)
    return res
