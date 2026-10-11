"""Optional Slither adapter (NOT installed in this environment).

Wiring, once `pip install slither-analyzer` + a solc binary (solc-select) are available:
    findings = run_slither(path)          # subprocess: slither <path> --json - (no network, timeout)
Slither compiles the sources with solc (it does not execute contract code). Its detectors are mapped to
EngineFinding with status CANDIDATE (High/Medium impact + High/Medium confidence) or NEEDS_REVIEW (others),
never CONFIRMED. The JSON mapping (`map_slither_json`) is testable without Slither.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..engines.contract import DependencyMissing, EngineFinding, Evidence

ENGINE = "contracts.slither/1"
_IMPACT = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info", "Optimization": "info"}
_CONF = {"High": 0.6, "Medium": 0.45, "Low": 0.25}


def slither_available() -> str:
    return shutil.which("slither") or ""


def run_slither(path: str, timeout: int = 600) -> list[EngineFinding]:
    exe = slither_available()
    if not exe:
        raise DependencyMissing("slither is not installed (pip install slither-analyzer; requires solc)")
    proc = subprocess.run([exe, str(path), "--json", "-"], capture_output=True, text=True, timeout=timeout,
                          check=False)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"slither produced no JSON (rc={proc.returncode}): {proc.stderr[-300:]}") from exc
    ver = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False).stdout.strip()
    return map_slither_json(data, str(path), ver)


def map_slither_json(data: dict, target: str, version: str = "") -> list[EngineFinding]:
    out = []
    for det in (data.get("results") or {}).get("detectors") or []:
        impact, conf = det.get("impact", "Informational"), det.get("confidence", "Low")
        elems = det.get("elements") or []
        sm = (elems[0].get("source_mapping") or {}) if elems else {}
        fn = next((e.get("name") for e in elems if e.get("type") == "function"), "")
        contract = next((e.get("name") for e in elems if e.get("type") == "contract"), "") or next(
            ((e.get("type_specific_fields") or {}).get("parent", {}).get("name", "") for e in elems
             if e.get("type") == "function"), "")
        lines = sm.get("lines") or []
        strong = impact in ("High", "Medium") and conf in ("High", "Medium")
        out.append(EngineFinding(
            engine=ENGINE, target=target, rule=f"slither:{det.get('check', '?')}", category=det.get("check", "?"),
            severity=_IMPACT.get(impact, "info"), confidence=_CONF.get(conf, 0.25),
            description=(det.get("description") or "").strip()[:500],
            evidence=[Evidence("tool-output", (det.get("description") or "").strip()[:300],
                               f"{sm.get('filename_relative', '')}:{lines[0] if lines else ''}", "moderate")],
            validation_method="tool", status="CANDIDATE" if strong else
            ("OBSERVATION" if impact in ("Informational", "Optimization") else "NEEDS_REVIEW"),
            limitations=["Slither detector output, not validated by a test or exploit"],
            location={"file": sm.get("filename_relative", ""), "line": lines[0] if lines else 0,
                      "contract": contract, "function": fn},
            tool={"name": "slither", "version": version}))
    return out
