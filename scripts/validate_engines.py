#!/usr/bin/env python3
"""Measure an engine against an independently labelled validation corpus (tests/fixtures/validation/<engine>/).

Labels are frozen BEFORE the engine is run (FROZEN.sha256 next to labels.json); this script refuses to measure
if the frozen hashes do not match. Two views are reported:
  strict   only CANDIDATE counts as a detection (NEEDS_REVIEW is NOT a confirmed finding)
  flagged  CANDIDATE or NEEDS_REVIEW counts as "brought to a human"
Findings matching no label are listed as `unlabeled` (to adjudicate separately, never folded into the metrics).

Usage: scripts/validate_engines.py contracts|web [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VAL = ROOT / "tests" / "fixtures" / "validation"
RANK = {"CANDIDATE": 3, "NEEDS_REVIEW": 2, "OBSERVATION": 1, "FALSE_POSITIVE": 0}


def check_frozen(d: Path) -> None:
    for line in (d / "FROZEN.sha256").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        if hashlib.sha256((d / name).read_bytes()).hexdigest() != digest:
            raise SystemExit(f"{d / name}: changed after the labels were frozen; refusing to measure")


def _ratio(a: int, b: int):
    return round(a / b, 3) if b else None


def measure(labels: list[dict], findings: list[dict], key_of_label, keys_of_finding, rule_map: dict,
            ignore_unlabeled: tuple = ()) -> dict:
    per_rule: dict[str, dict] = {}
    matched_ids: set[int] = set()
    cases = []
    for lab in labels:
        rules = rule_map.get(lab["category"], [])
        hits = [(i, f) for i, f in enumerate(findings)
                if f["rule"] in rules and key_of_label(lab) in keys_of_finding(f)]
        matched_ids |= {i for i, _ in hits}
        best = max((f["status"] for _, f in hits), key=lambda s: RANK.get(s, 0), default="NONE")
        t = lab["truth"]
        if not lab.get("in_scope", True):
            outcome = "out_of_scope_detected" if best in ("CANDIDATE", "NEEDS_REVIEW") else "out_of_scope_missed"
        elif t == "VULN":
            outcome = {"CANDIDATE": "TP", "NEEDS_REVIEW": "TP_review"}.get(best, "FN")
        elif t == "SAFE":
            outcome = {"CANDIDATE": "FP", "NEEDS_REVIEW": "FP_review", "OBSERVATION": "FP_observation"}.get(best, "TN")
        elif t == "FACT":                     # configuration fact: expected as OBSERVATION, never as a vulnerability
            outcome = {"OBSERVATION": "FACT_observed", "NONE": "FACT_missed"}.get(best, "FACT_overclaimed")
        else:
            outcome = f"ambiguous_{best.lower()}"
        cases.append({**lab, "engine_status": best, "outcome": outcome, "rules_hit": sorted({f['rule'] for _, f in hits})})
        r = per_rule.setdefault(lab["category"], {})
        r[outcome] = r.get(outcome, 0) + 1
    unlabeled = [f for i, f in enumerate(findings) if i not in matched_ids]
    ignored = [f for f in unlabeled if f["rule"].startswith(ignore_unlabeled)] if ignore_unlabeled else []
    unlabeled = [f for f in unlabeled if f not in ignored]
    c = {o: sum(1 for x in cases if x["outcome"] == o) for o in
         ("TP", "TP_review", "FN", "FP", "FP_review", "FP_observation", "TN",
          "FACT_observed", "FACT_missed", "FACT_overclaimed")}
    vul = c["TP"] + c["TP_review"] + c["FN"]
    safe = c["FP"] + c["FP_review"] + c["TN"]
    metrics = {
        "counts": c, "vulnerable_in_scope": vul, "safe": safe,
        "strict": {"precision": _ratio(c["TP"], c["TP"] + c["FP"]), "recall": _ratio(c["TP"], vul),
                   "fp_rate": _ratio(c["FP"], safe), "fn_rate": _ratio(c["FN"] + c["TP_review"], vul)},
        "flagged": {"precision": _ratio(c["TP"] + c["TP_review"], c["TP"] + c["TP_review"] + c["FP"] + c["FP_review"]),
                    "recall": _ratio(c["TP"] + c["TP_review"], vul),
                    "fp_rate": _ratio(c["FP"] + c["FP_review"], safe), "fn_rate": _ratio(c["FN"], vul)},
        "facts": {"observed": c["FACT_observed"], "missed": c["FACT_missed"], "overclaimed": c["FACT_overclaimed"]},
        "needs_review_rate": _ratio(sum(1 for f in findings if f["status"] == "NEEDS_REVIEW"), len(findings)),
        "ambiguous": {x["id"]: x["engine_status"] for x in cases if x["truth"] == "AMBIGUOUS"},
        "out_of_scope": {x["id"]: x["outcome"] for x in cases if not x.get("in_scope", True)},
    }
    return {"metrics": metrics, "per_category": per_rule, "cases": cases, "ignored_unlabeled": len(ignored),
            "unlabeled": [{k: f[k] for k in ("rule", "status", "location")} for f in unlabeled]}


def contracts() -> dict:
    from github_security.contracts import run
    d = VAL / "contracts"
    check_frozen(d)
    doc = json.loads((d / "labels.json").read_text())
    runs = [run(str(d)) for _ in range(2)]
    same = json.dumps(runs[0]["findings"], sort_keys=True) == json.dumps(runs[1]["findings"], sort_keys=True)
    r = runs[0]
    out = measure(doc["labels"], r["findings"],
                  lambda lab: (lab["file"], lab["contract"], lab["function"]),
                  lambda f: {(Path(f["location"].get("file", "")).name, f["location"].get("contract"),
                              f["location"].get("function"))},
                  doc["rule_map"])
    out["engine"] = r["engine"]
    out["parse_errors"] = r["parse_errors"]
    out["files"] = len(r["files_scanned"])
    out["reproducible"] = same
    return out


def web() -> dict:
    from github_security.web.engine import run
    d = VAL / "web"
    check_frozen(d)
    doc = json.loads((d / "labels.json").read_text())
    runs = [run(str(d / "corpus")) for _ in range(2)]
    same = json.dumps(runs[0]["findings"], sort_keys=True) == json.dumps(runs[1]["findings"], sort_keys=True)
    r = runs[0]

    def fkeys(f):
        src = f["location"].get("source") or ""
        return {Path(str(src).split("#")[0]).name}          # JSON captures: "<file>.json#<exchange index>"
    out = measure(doc["labels"], r["findings"], lambda lab: lab["file"], fkeys, doc["rule_map"],
                  tuple(doc.get("ignore_unlabeled_prefixes", ())))
    out["engine"] = r["engine"]
    errs = r["inputs"].get("errors") or []
    out["input_errors"] = errs
    out["expected_input_errors_reported"] = all(any(e_name in json.dumps(e) for e in errs)
                                                for e_name in doc.get("expected_input_errors", []))
    out["findings_on_malformed_inputs"] = [f["rule"] for f in r["findings"] if
                                           Path(str(f["location"].get("source", "")).split("#")[0]).name in
                                           doc.get("expected_input_errors", [])]
    out["reproducible"] = same
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("engine", choices=["contracts", "web"])
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    sys.path.insert(0, str(ROOT / "src"))
    res = contracts() if a.engine == "contracts" else web()
    if a.json:
        print(json.dumps(res, indent=1, default=str))
        return 0
    print(f"{res['engine']}  reproducible={res['reproducible']}  ignored_unlabeled={res.get('ignored_unlabeled')}")
    for k in ("input_errors", "expected_input_errors_reported", "findings_on_malformed_inputs", "parse_errors"):
        if k in res:
            print(f"{k}: {res[k]}")
    print(json.dumps(res["metrics"], indent=1))
    for x in res["cases"]:
        if x["outcome"] not in ("TP", "TN", "FACT_observed"):
            print(f"  {x['outcome']:<22} {x['id']:<5} {x['category']:<16} {x.get('contract', '')}.{x.get('function', '')}"
                  f" {x.get('file', '')} engine={x['engine_status']} {x['rules_hit']}")
    for f in res["unlabeled"]:
        print(f"  UNLABELED {f['status']:<13} {f['rule']:<26} {f['location']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
