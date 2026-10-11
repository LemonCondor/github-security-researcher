"""web.passive/2 — offline passive web analysis over captured HTTP exchanges and static resources.

Entry point for the CLI integration: ``run(path) -> dict`` (JSON-serialisable). No network I/O of any kind.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..engines.contract import EngineFinding
from . import capture, checks

ENGINE = "web.passive/2"
GLOBAL_LIMITATIONS = [
    "passive analysis of supplied captures/files only: no request was sent, nothing was re-fetched",
    "statuses are OBSERVATION / CANDIDATE / NEEDS_REVIEW only; nothing here is a confirmed vulnerability",
    "absence of findings does not mean the site is secure (only the captured responses were seen)",
]


def analyze(exchanges: list[capture.Exchange], target: str) -> list[EngineFinding]:
    found: dict[tuple, EngineFinding] = {}
    for ex in exchanges:
        for check in checks.ALL_CHECKS:
            for key, kw in check(ex):
                key = (kw["rule"],) + tuple(key)
                if key in found:
                    found[key].extra["occurrences"] = found[key].extra.get("occurrences", 1) + 1
                    continue
                kw["extra"].setdefault("occurrences", 1)
                found[key] = EngineFinding(engine=ENGINE, target=target, **kw)
    return list(found.values())


def run(path: str | Path) -> dict:
    target = str(path)
    exchanges, errors = capture.load(path)
    findings = analyze(exchanges, target)
    na: dict[str, list[str]] = {}
    for ex in exchanges:
        reason = checks.not_applicable(ex)
        if reason:
            na.setdefault(reason, []).append(ex.source)
    return {
        "engine": ENGINE,
        "target": target,
        "inputs": {"exchanges": sum(e.kind == "http" for e in exchanges),
                   "resources": sum(e.kind == "resource" for e in exchanges), "errors": errors},
        "network": "none",
        "summary": {"total": len(findings), "by_status": dict(Counter(f.status for f in findings)),
                    "by_rule": dict(sorted(Counter(f.rule for f in findings).items()))},
        "findings": [f.to_dict() for f in findings],
        "not_applicable": [{"checks": list(checks.HTML_ONLY_CHECKS), "reason": r, "responses": srcs}
                           for r, srcs in sorted(na.items())],
        "limitations": GLOBAL_LIMITATIONS,
    }


def render_text(result: dict) -> str:
    lines = [f"{result['engine']}  target={result['target']}  exchanges={result['inputs']['exchanges']} "
             f"resources={result['inputs']['resources']}  findings={result['summary']['total']}  network=none"]
    for err in result["inputs"]["errors"]:
        lines.append(f"  ! input error: {err}")
    order = {"CANDIDATE": 0, "NEEDS_REVIEW": 1, "OBSERVATION": 2, "FALSE_POSITIVE": 3}
    for f in sorted(result["findings"], key=lambda f: (order[f["status"]], f["rule"])):
        loc = f["location"]
        where = loc.get("header") or loc.get("cookie") or loc.get("library") or loc.get("resource") or ""
        lines.append(f"  [{f['status']:<12}] {f['severity']:<6} {f['rule']:<40} {loc.get('url', '')} {where}")
    for na in result.get("not_applicable", []):
        lines.append(f"  [not applicable] {', '.join(na['checks'])}: {na['reason']} "
                     f"({len(na['responses'])} response(s))")
    lines.append("  note: " + GLOBAL_LIMITATIONS[1])
    return "\n".join(lines)
