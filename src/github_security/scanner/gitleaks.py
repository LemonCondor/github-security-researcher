"""Gitleaks adapter. Secret values are NEVER stored: gitleaks --redact + our own redaction."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..analysis.findings import Finding
from ..security.secrets import redact
from .base import Scanner, ScanTarget, run_tool, safe_relpath


class GitleaksScanner(Scanner):
    name = "gitleaks"

    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    def available(self) -> bool:
        return self._which("gitleaks")

    def scan(self, target: ScanTarget) -> list[Finding]:
        return self._run(target, target.path)

    def scan_file(self, target: ScanTarget, rel: str) -> list[Finding]:
        return self._run(target, target.path / rel)

    def _run(self, target: ScanTarget, scan_path) -> list[Finding]:
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "r.json"
            # `dir` mode = working tree only (history scanning is opt-in later).
            run_tool(["gitleaks", "dir", str(scan_path), "--no-banner", "--redact=100",
                      "--report-format", "json", "--report-path", str(report), "--exit-code", "0",
                      "--max-target-megabytes", "5", "--log-level", "error"],
                     timeout=self.timeout)
            items = json.loads(report.read_text() or "[]")
        findings = []
        for it in items:
            rel = safe_relpath(target.path, it["File"])
            rule = it.get("RuleID", "secret")
            # Evidence = location + rule, never the matched value.
            findings.append(Finding(
                repository=target.slug, commit=target.commit, file=rel,
                line=int(it.get("StartLine", 0)), end_line=int(it.get("EndLine", 0)) or None,
                rule=rule, category="secret", severity="high", confidence=0.6,
                scanner=self.name,
                description=redact(f"Potential hard-coded secret ({it.get('Description', rule)})"),
                # line-free so the fingerprint survives code moves
                evidence=f"{rule} match in {rel} (value redacted)",
                references=["https://cwe.mitre.org/data/definitions/798.html"],
            ))
        return findings
