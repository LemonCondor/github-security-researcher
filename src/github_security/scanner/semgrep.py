"""Semgrep adapter (internal rules + optional registry packs).

Raw Semgrep data is preserved in Finding.extra["semgrep"] (not part of the fingerprint).
Facts about Semgrep OSS 1.179 JSON output, verified 2026-10-07 (unauthenticated):
  * per result: check_id (prefixed by the config path for local rule files), path, start/end
    {line, col, offset}, extra {message, severity, metadata, engine_kind, validation_state, lines, fingerprint};
  * `lines` and `fingerprint` are the literal string "requires login" -> not stored;
  * `extra.metavars` is absent -> captured values are only visible interpolated in `message`;
  * `extra.dataflow_trace` is absent, even with --dataflow-traces -> no taint path is available;
  * the rule mode (taint/search) is not in the output -> known only for local rule files we load.
If a future Semgrep version provides metavars or a dataflow trace, they are stored (sanitised) as-is.
Nothing here is reconstructed or inferred.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from ..analysis.findings import CATEGORIES, CWE_ALIASES, Finding
from ..observability import event
from ..security.secrets import redact
from .base import Scanner, ScanTarget, read_line, run_tool, safe_relpath

_CWE_TO_CAT = {**{cwe: cat for cat, cwe in CATEGORIES.items() if cwe}, **CWE_ALIASES}
_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_CONF = {"HIGH": 0.7, "MEDIUM": 0.5, "LOW": 0.3}
INTERNAL_RULES = Path(__file__).resolve().parents[3] / "rules" / "semgrep"
_LOGIN_PLACEHOLDER = "requires login"
_META_KEYS = ("category", "subcategory", "confidence", "likelihood", "impact", "cwe", "owasp",
              "vulnerability_class", "technology", "source", "shortlink", "interfile",
              "gsr_category", "gsr_source", "gsr_sink")
_MODE_UNAVAILABLE = "unavailable: not in Semgrep OSS JSON output (registry/remote rule)"


def _category(meta: dict, rule_id: str) -> str:
    if not isinstance(meta, dict):
        meta = {}
    if meta.get("gsr_category") in CATEGORIES:
        return meta["gsr_category"]
    cwes = meta.get("cwe") or []
    for c in cwes if isinstance(cwes, list) else [cwes]:
        m = re.match(r"(CWE-\d+)", str(c))
        if m and m.group(1) in _CWE_TO_CAT:
            return _CWE_TO_CAT[m.group(1)]
    rid = str(rule_id).lower()
    for key, cat in (("sql", "sql-injection"), ("ssrf", "ssrf"), ("xss", "xss"),
                     ("path-traversal", "path-traversal"), ("command", "command-injection"),
                     ("subprocess", "command-injection"), ("deserial", "insecure-deserialization"),
                     ("pickle", "insecure-deserialization")):
        if key in rid:
            return cat
    return "other"


# ------------------------------------------------------------------ sanitising helpers

def _clean(v, depth: int = 0):
    """JSON-safe, size-bounded, redacted copy of untrusted scanner data."""
    if depth > 4:
        return None
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v if v == v and abs(v) < 1e15 else None          # drop NaN/inf/absurd numbers
    if isinstance(v, str):
        return redact(v)[:500]
    if isinstance(v, (list, tuple)):
        return [_clean(x, depth + 1) for x in list(v)[:20]]
    if isinstance(v, dict):
        return {str(k)[:100]: _clean(x, depth + 1) for k, x in list(v.items())[:30]}
    return redact(str(v))[:200]


def _int(x) -> int | None:
    if isinstance(x, bool):
        return None
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


def _pos(p) -> dict | None:
    if not isinstance(p, dict):
        return None
    out = {k: _int(p.get(k)) for k in ("line", "col", "offset")}
    return out if any(v is not None for v in out.values()) else None


def short_rule_id(check_id: str) -> str:
    """Historical short id (last dotted segment). Kept: it is part of existing fingerprints."""
    return str(check_id).split(".")[-1]


def load_rule_modes(configs: list[str]) -> dict[str, str]:
    """rule id -> 'taint' | 'search', for LOCAL rule files only (as declared in their YAML)."""
    modes: dict[str, str] = {}
    for c in configs:
        p = Path(c)
        if not p.exists():
            continue                                   # registry pack (p/..., r/...) or URL
        files = [p] if p.is_file() else sorted([*p.rglob("*.yaml"), *p.rglob("*.yml")])
        for f in files:
            try:
                doc = yaml.safe_load(f.read_text())
            except (OSError, yaml.YAMLError):
                continue
            for rule in (doc or {}).get("rules", []) if isinstance(doc, dict) else []:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                    modes[rule["id"]] = rule.get("mode", "search") if rule.get("mode") in ("taint", "search", "join", "extract") else "search"
    return modes


def _rule_mode(check_id: str, modes: dict[str, str]) -> tuple[str | None, str]:
    if check_id in modes:
        return modes[check_id], "local rule file"
    for rid, mode in modes.items():                    # local rules: check_id = <config path prefix>.<id>
        if check_id.endswith("." + rid):
            return mode, "local rule file"
    return None, _MODE_UNAVAILABLE


def semgrep_extra(r: dict, rule_modes: dict[str, str]) -> dict:
    """Everything useful Semgrep actually returned for one result (sanitised, nothing invented)."""
    extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
    meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    check_id = str(r.get("check_id", ""))[:300]
    mode, mode_src = _rule_mode(check_id, rule_modes)
    refs = meta.get("references") or []
    out = {
        "check_id": check_id,
        "rule_short_id": short_rule_id(check_id),
        "message": redact(str(extra.get("message", "")))[:2000],
        "severity_raw": _clean(extra.get("severity")),
        "confidence_raw": _clean(meta.get("confidence")),
        "engine_kind": _clean(extra.get("engine_kind")),
        "validation_state": _clean(extra.get("validation_state")),
        "start": _pos(r.get("start")),
        "end": _pos(r.get("end")),
        "metadata": {k: _clean(meta[k]) for k in _META_KEYS if k in meta},
        "references": [redact(str(x))[:500] for x in (refs if isinstance(refs, list) else [refs])][:10],
        "rule_mode": mode,
        "rule_mode_source": mode_src,
        "metavars": _clean(extra["metavars"]) if isinstance(extra.get("metavars"), dict) else None,
        "dataflow_trace": _clean(extra["dataflow_trace"]) if isinstance(extra.get("dataflow_trace"), dict) else None,
    }
    for k in ("lines", "fingerprint"):                # only if real data, never the login placeholder
        v = extra.get(k)
        if isinstance(v, str) and v and v != _LOGIN_PLACEHOLDER:
            out[k] = redact(v)[:1000]
    out["not_provided_by_semgrep"] = [k for k in ("metavars", "dataflow_trace") if out[k] is None]
    return out


def parse_results(out: dict, target: ScanTarget, scanner_name: str, rule_modes: dict[str, str]) -> list[Finding]:
    findings = []
    results = out.get("results") if isinstance(out, dict) else None
    for r in results if isinstance(results, list) else []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        meta = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        check_id, path = r.get("check_id"), r.get("path")
        line = _int((r.get("start") or {}).get("line")) if isinstance(r.get("start"), dict) else None
        if not isinstance(check_id, str) or not check_id or not isinstance(path, str) or not line or line < 1:
            event("scan", "semgrep.result_skipped", reason="malformed result",
                  check_id=str(check_id)[:200] if check_id is not None else None)
            continue
        rel = safe_relpath(target.path, path)          # refuses paths escaping the repository
        end_line = _int((r.get("end") or {}).get("line")) if isinstance(r.get("end"), dict) else None
        snippet = read_line(target.path, rel, line)
        refs = meta.get("references") or []
        findings.append(Finding(
            repository=target.slug, commit=target.commit, file=rel, line=line,
            end_line=end_line if end_line and end_line >= line else line, rule=short_rule_id(check_id),
            category=_category(meta, check_id),
            severity=_SEV.get(str(meta.get("impact") or extra.get("severity", "")).upper(), "medium"),
            confidence=_CONF.get(str(meta.get("confidence", "")).upper(), 0.4),
            scanner=scanner_name, description=redact(str(extra.get("message", "")))[:1000],
            evidence=redact(snippet),
            source=meta.get("gsr_source") if isinstance(meta.get("gsr_source"), str) else None,
            sink=meta.get("gsr_sink") if isinstance(meta.get("gsr_sink"), str) else None,
            references=[str(x) for x in (refs if isinstance(refs, list) else [refs])][:5],
            extra={"semgrep": semgrep_extra(r, rule_modes)},
        ))
    return findings


class SemgrepScanner(Scanner):
    name = "semgrep"

    def __init__(self, configs: list[str] | None = None, timeout: int = 900):
        self.configs = configs or [str(INTERNAL_RULES)]
        self.timeout = timeout
        self._modes: dict[str, str] | None = None

    def available(self) -> bool:
        return self._which("semgrep")

    def scan(self, target: ScanTarget) -> list[Finding]:
        return self._run(target, target.path)

    def scan_file(self, target: ScanTarget, rel: str) -> list[Finding]:
        """Static re-run on one file (parses only; never executes the code)."""
        return self._run(target, target.path / rel)

    def rule_modes(self) -> dict[str, str]:
        if self._modes is None:
            self._modes = load_rule_modes(self.configs)
        return self._modes

    def _run(self, target: ScanTarget, scan_path) -> list[Finding]:
        cmd = ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
               "--timeout", "30", "--max-target-bytes", "1000000", "--no-git-ignore"]
        for c in self.configs:
            cmd += ["--config", c]
        cmd.append(str(scan_path))
        out = json.loads(run_tool(cmd, timeout=self.timeout, ok_codes=(0, 1)))
        return parse_results(out, target, self.name, self.rule_modes())
