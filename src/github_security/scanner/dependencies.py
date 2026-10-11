"""Dependency vulnerabilities via the OSV.dev API.

Lockfiles are PARSED, never installed or executed (pip-audit -r would build untrusted sdists).
Only package names + versions leave the machine.
"""
from __future__ import annotations

import json
import re
import tomllib
import urllib.request
from pathlib import Path

from ..analysis.findings import Finding
from .base import Scanner, ScannerError, ScanTarget

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
_SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "third_party"}
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_-]+)")


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str):
    for line in text.splitlines():
        m = _REQ.match(line.split("#", 1)[0])
        if m:
            yield "PyPI", _norm_py(m.group(1)), m.group(2), line.strip()


def parse_package_lock(text: str):
    data = json.loads(text)
    for path, meta in (data.get("packages") or {}).items():
        if not path or not meta.get("version") or meta.get("link"):
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        yield "npm", name, meta["version"], f"{name}@{meta['version']}"
    for name, meta in (data.get("dependencies") or {}).items():  # lockfile v1
        if not data.get("packages") and isinstance(meta, dict) and meta.get("version"):
            yield "npm", name, meta["version"], f"{name}@{meta['version']}"


def parse_toml_lock(text: str, ecosystem: str):
    for pkg in tomllib.loads(text).get("package", []):
        if pkg.get("name") and pkg.get("version"):
            name = _norm_py(pkg["name"]) if ecosystem == "PyPI" else pkg["name"]
            yield ecosystem, name, pkg["version"], f"{pkg['name']}=={pkg['version']}"


def parse_go_mod(text: str):
    for m in re.finditer(r"^\s*(?:require\s+)?([a-z0-9.\-]+\.[a-z]{2,}/[^\s]+)\s+(v[^\s]+)", text, re.M):
        yield "Go", m.group(1), m.group(2), f"{m.group(1)} {m.group(2)}"


PARSERS = {
    "package-lock.json": parse_package_lock,
    "poetry.lock": lambda t: parse_toml_lock(t, "PyPI"),
    "uv.lock": lambda t: parse_toml_lock(t, "PyPI"),
    "Cargo.lock": lambda t: parse_toml_lock(t, "crates.io"),
    "go.mod": parse_go_mod,
}


def discover(root: Path):
    """Yield (relpath, ecosystem, name, version, evidence) for pinned deps."""
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts[:-1]) or p.is_symlink() or not p.is_file():
            continue
        if p.stat().st_size > 20_000_000:
            continue
        parser = PARSERS.get(p.name)
        if parser is None and re.fullmatch(r"requirements[\w.-]*\.txt", p.name):
            parser = parse_requirements
        if parser is None:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
            for eco, name, ver, ev in parser(text):
                yield str(rel), eco, name, ver, ev
        except (ValueError, tomllib.TOMLDecodeError):
            continue


def _line_of(root: Path, rel: str, needle: str) -> int:
    for i, l in enumerate((root / rel).read_text(errors="replace").splitlines(), 1):
        if needle.split("@")[0].split("==")[0].split(" ")[0] in l:
            return i
    return 1


def _post(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def _get(url: str, timeout: int) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def _severity(vuln: dict) -> str:
    sev = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    return {"moderate": "medium", "critical": "critical", "high": "high", "low": "low",
            "medium": "medium"}.get(sev, "medium")


def trim_advisory(vuln: dict, ecosystem: str, name: str, version: str) -> dict:
    """Structured, size-bounded subset of an OSV record for the matching package (no free-form blobs)."""
    affected = []
    for a in vuln.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("name") != name and _norm_py(pkg.get("name", "")) != name:
            continue
        ranges = [{"type": r.get("type"), "events": r.get("events", [])[:20]} for r in (a.get("ranges") or [])[:5]]
        eco_spec = a.get("ecosystem_specific") or {}
        imports_ = [{"path": i.get("path"), "symbols": (i.get("symbols") or [])[:30]}
                    for i in (eco_spec.get("imports") or [])[:20]]
        affected.append({"package": pkg.get("name"), "ecosystem": pkg.get("ecosystem"), "ranges": ranges,
                         "affected_imports_and_symbols": imports_})
    fixed = sorted({e["fixed"] for a in affected for r in a["ranges"] for e in r["events"] if "fixed" in e})
    return {
        "id": vuln.get("id"),
        "aliases": (vuln.get("aliases") or [])[:10],
        "package": name, "ecosystem": ecosystem, "installed_version": version,
        "summary": (vuln.get("summary") or "")[:500],
        "details": (vuln.get("details") or "")[:3000],
        "severity": (vuln.get("database_specific") or {}).get("severity"),
        "cvss": [x.get("score") for x in (vuln.get("severity") or [])][:3],
        "affected": affected,
        "fixed_versions": fixed,
        "published": vuln.get("published"), "modified": vuln.get("modified"),
        "references": [{"type": r.get("type"), "url": r.get("url")} for r in (vuln.get("references") or [])[:10]],
        "source": "https://osv.dev/vulnerability/" + str(vuln.get("id")),
    }


def fetch_advisory(vid: str, ecosystem: str, name: str, version: str, get=None, timeout: int = 30) -> dict:
    return trim_advisory((get or _get)(OSV_VULN + vid, timeout), ecosystem, name, version)


class OSVDependencyScanner(Scanner):
    name = "osv"

    def __init__(self, timeout: int = 60, post=_post, get=_get):
        self.timeout, self._post, self._get = timeout, post, get

    def available(self) -> bool:
        return True

    def scan(self, target: ScanTarget) -> list[Finding]:
        deps = list(dict.fromkeys(discover(target.path)))
        if not deps:
            return []
        results = []
        try:
            for i in range(0, len(deps), 500):
                chunk = deps[i:i + 500]
                q = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v}
                                 for _, e, n, v, _ in chunk]}
                results += self._post(OSV_BATCH, q, self.timeout).get("results", [])
        except OSError as e:
            raise ScannerError(f"OSV query failed: {e}") from e

        details: dict[str, dict] = {}
        findings = []
        for (rel, eco, name, ver, ev), res in zip(deps, results):
            seen: set[str] = set()   # PYSEC-x and GHSA-y are often the same advisory
            for v in sorted(res.get("vulns") or [], key=lambda v: not v["id"].startswith("GHSA")):
                vid = v["id"]
                if vid in seen:
                    continue
                if vid not in details:
                    try:
                        details[vid] = self._get(OSV_VULN + vid, self.timeout)
                    except OSError:
                        details[vid] = {"id": vid}
                d = details[vid]
                aliases = d.get("aliases") or []
                if seen & set(aliases):
                    continue
                seen |= {vid, *aliases}
                findings.append(Finding(
                    repository=target.slug, commit=target.commit, file=rel,
                    line=_line_of(target.path, rel, ev), rule=vid, category="vulnerable-dependency",
                    severity=_severity(d), confidence=0.5, scanner=self.name,
                    description=(d.get("summary") or f"{name} {ver} is affected by {vid}")[:500],
                    evidence=f"{eco}:{name}=={ver}",
                    references=[f"https://osv.dev/vulnerability/{vid}", *aliases][:5],
                    extra={"advisory": trim_advisory(d, eco, name, ver)} if d.get("affected") else {},
                ))
        return findings
