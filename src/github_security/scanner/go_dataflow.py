"""GoDataflow as a scanner: inter-procedural source -> sink paths become CANDIDATE findings.

Purely static (tree-sitter parse of local .go files). Every finding is a *potential* flow: it carries
the structured path in extra["go_dataflow"] and is re-established, as evidence, by the static step
`static.go_dataflow`. It can never be CONFIRMED on its own (SOURCE_TO_SINK moderate, see evidence.py).
"""
from __future__ import annotations

import time

from ..analysis import go_dataflow as gd
from ..analysis.findings import Finding
from ..observability import event
from ..validation.static import _NONPROD
from .base import Scanner, ScanTarget, read_line

MAX_PATHS_PER_FINDING = 5
_SEVERITY = {"command-injection": "high", "sql-injection": "high", "ssrf": "medium", "path-traversal": "medium"}
_WHAT = {"command-injection": "a command executed by os/exec",
         "sql-injection": "the text of a database/sql query",
         "path-traversal": "a file path (path traversal NOT established: no check of the path is modelled)",
         "ssrf": "the destination URL of an outgoing HTTP request"}


def path_summary(p: gd.FlowPath) -> str:
    return f"{p.source.detail} -> {' -> '.join(p.functions())} -> {p.sink.detail}"


def findings_from_result(res: gd.AnalysisResult, target: ScanTarget) -> tuple[list[Finding], dict]:
    groups: dict[tuple[str, int, str], list[gd.FlowPath]] = {}
    skipped_nonprod = 0
    for p in res.paths:
        if p.truncated or p.sink is None or not p.category:
            continue
        if p.source.kind == "source_operator":
            continue                       # operator flags/env: diagnostics only, never user-input findings
        if _NONPROD.search(p.sink.file) or _NONPROD.search(p.source.file):
            skipped_nonprod += 1           # same policy as Semgrep's default test exclusion
            continue
        groups.setdefault((p.sink.file, p.sink.line, p.category), []).append(p)
    out = []
    for (file, line, cat), paths in sorted(groups.items()):
        paths.sort(key=lambda p: (p.depth, p.source.file, p.source.line))
        first = paths[0]
        out.append(Finding(
            repository=target.slug, commit=target.commit, file=file, line=line,
            rule=f"go-dataflow.{cat}", category=cat, severity=_SEVERITY.get(cat, "medium"),
            confidence=0.4, scanner="go_dataflow",
            description=(f"Statically resolved flow (potential, not confirmed): an HTTP request value reaches "
                         f"{_WHAT.get(cat, cat)}. {path_summary(first)}"),
            evidence=read_line(target.path, file, line),
            source=f"{first.source.file}:{first.source.line} {first.source.detail}",
            sink=first.sink.detail,
            extra={"go_dataflow": {
                "engine": res.engine, "status": gd.PATH_STATUS, "path_count": len(paths),
                "paths": [p.to_dict() for p in paths[:MAX_PATHS_PER_FINDING]],
                "max_depth_hops": max(p.depth for p in paths),
                "crosses_files": any(len(p.files()) > 1 for p in paths)}}))
    stats = {"paths": len(res.paths), "findings": len(out), "skipped_non_production": skipped_nonprod,
             "tainted_no_proof": len(res.tainted_no_proof), "neutralized": len(res.neutralized),
             "files": len(res.files), "functions": len(res.functions), "parse_errors": len(res.parse_errors),
             "budget_exhausted": res.budget_exhausted}
    return out, stats


class GoDataflowScanner(Scanner):
    name = "go_dataflow"

    def available(self) -> bool:
        return gd.available()

    def scan(self, target: ScanTarget) -> list[Finding]:
        t0 = time.monotonic()
        res = gd.analyze_security(target.path)
        out, stats = findings_from_result(res, target)
        event("scan", "go_dataflow.stats", repository=target.slug, duration_ms=int((time.monotonic() - t0) * 1000),
              **stats)
        return out
