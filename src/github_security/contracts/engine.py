"""contracts.solidity/2 — local, syntax-only Solidity pattern engine. Reads .sol files, never compiles or
executes them, no network. Entry point: run(path) -> dict (proposed CLI: `github-sec contracts scan PATH [--json]`).
"""
from __future__ import annotations

from pathlib import Path

from ..engines.contract import EngineFinding, Evidence
from . import coverage
from .analysis import FunctionFacts
from .parser import Project, get_parser, parse_file
from .rules import RULES, FUNCTION_RULES, pragma_is_legacy, rule_legacy_arith, rule_tx_origin

ENGINE = "contracts.solidity/2"
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {"node_modules", ".git", "lib", "cache", "out", "artifacts"}

BASE_LIMITATIONS = [
    "syntax pattern only (tree-sitter), no compilation or type resolution",
    "not validated by a test, fuzzing or symbolic execution: exploitability is not proven",
]


def collect_files(path: Path) -> list[Path]:
    path = Path(path)
    if path.is_file():
        return [path] if path.suffix == ".sol" else []
    root = path.resolve()
    out = []
    for p in sorted(path.rglob("*.sol")):
        if any(part in SKIP_DIRS for part in p.relative_to(path).parts[:-1]):
            continue
        if p.is_symlink() and root not in p.resolve().parents:
            continue            # never follow a symlink out of the scanned tree
        if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES:
            out.append(p)
    return out


def _to_finding(hit, sf, target: str, tool: dict) -> EngineFinding:
    category, _, title = RULES[hit.rule]
    ev = [Evidence("code", sf.code_line(n)[:200], f"{sf.path}:{n}", "moderate") for n in hit.evidence_lines]
    status = hit.status
    limitations = list(BASE_LIMITATIONS)
    if hit.suppressed:
        status = "FALSE_POSITIVE"
        ev.append(Evidence("negative", hit.suppressed, f"{sf.path}:{hit.line}", hit.suppressed_strength))
        if hit.suppressed_strength != "strong":
            limitations.append("negative evidence is name-based: the guard's implementation was not verified")
    if sf.has_error:
        limitations.append("file has parse errors: some constructs may be missed")
    return EngineFinding(
        engine=ENGINE, target=target, rule=hit.rule, category=category, severity=hit.severity,
        confidence=hit.confidence, description=f"{title}: {hit.description}", evidence=ev,
        references=[], validation_method="ast", status=status, limitations=limitations,
        location={"file": sf.path, "line": hit.line, "contract": hit.contract, "function": hit.function},
        tool=tool, extra=dict(hit.extra))


def scan(path, include_suppressed: bool = False) -> tuple[list[EngineFinding], dict]:
    path = Path(path)
    _, parser_version = get_parser()
    tool = {"name": "github-sec contracts.solidity", "version": "2", "parser": parser_version}
    files = collect_files(path)
    base = path if path.is_dir() else path.parent
    sources = [parse_file(p, str(p.relative_to(base))) for p in files]
    project = Project(sources)
    target = str(path)
    findings, suppressed = [], 0
    for sf in sources:
        legacy = pragma_is_legacy(sf)
        for c in sf.contracts:
            if c.kind == "interface":
                continue
            for fn in c.functions:
                facts = FunctionFacts(fn, project)
                hits = [h for rule in FUNCTION_RULES for h in rule(facts)]
                hits += list(rule_legacy_arith(facts, legacy))
                for h in hits:
                    if h.suppressed:
                        suppressed += 1
                        if not include_suppressed:
                            continue
                    findings.append(_to_finding(h, sf, target, tool))
            for mod in c.modifiers.values():
                for h in rule_tx_origin(FunctionFacts(mod, project)):
                    findings.append(_to_finding(h, sf, target, tool))
    meta = {"tool": tool, "files_scanned": [s.path for s in sources],
            "parse_errors": [s.path for s in sources if s.has_error],
            "contracts": sum(len(s.contracts) for s in sources), "suppressed": suppressed}
    return findings, meta


def run(path, include_suppressed: bool = False) -> dict:
    """Scan PATH (file or directory). Returns a JSON-serialisable report. Raises DependencyMissing if the
    Solidity grammar is not installed."""
    findings, meta = scan(path, include_suppressed=include_suppressed)
    by_status: dict[str, int] = {}
    for f in findings:
        by_status[f.status] = by_status.get(f.status, 0) + 1
    return {
        "engine": ENGINE, "target": str(path), **meta,
        "summary": {"findings": len(findings), "by_status": by_status},
        "findings": [f.to_dict() for f in findings],
        "coverage": {"implemented": coverage.IMPLEMENTED, "documented_only": coverage.DOCUMENTED_ONLY,
                     "assumptions": coverage.ASSUMPTIONS},
    }
