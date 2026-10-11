"""End-to-end evaluation on the synthetic fixture (ground truth in tests/fixtures/vulnapp/expected.yaml).

    python scripts/evaluate.py [--llm] [--out data/eval]

Markers (# VULN:..., # SAFE...) are stripped before scanning so neither the scanners nor the
LLM can read the answers. Nothing from the fixture is executed.
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import shutil
import string
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_security import observability as obs  # noqa: E402
from github_security.pipeline import review_finding, scan_and_store, validate_finding  # noqa: E402
from github_security.scanner.base import ScanTarget  # noqa: E402
from github_security.scanner.runner import default_scanners  # noqa: E402
from github_security.storage.database import Database  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "vulnapp"


def prepare(dst: Path) -> dict:
    shutil.copytree(FIXTURE, dst)
    truth = yaml.safe_load((dst / "expected.yaml").read_text())
    (dst / "expected.yaml").unlink()
    src = (dst / "app.py").read_text().splitlines()
    expected, safe = set(), set()
    for v in truth["vulnerabilities"]:
        if v["file"] == "app.py":
            for i, l in enumerate(src, 1):
                if v["marker"] in l:
                    expected.add((v["category"], "app.py", i))
    for i, l in enumerate(src, 1):
        if "SAFE" in l:
            safe.add(i)
    clean = [re.sub(r"\s*#\s*(VULN:[\w-]+|SAFE).*$", "", l) for l in src]
    clean = [l.replace("    # VULN:auth-bypass -- trusts a client-controlled header as authentication", "    #")
             for l in clean]
    (dst / "app.py").write_text("\n".join(clean) + "\n")
    tok = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (dst / "config.py").write_text(f'# deployment settings\nGITHUB_TOKEN = "{tok}"\n')
    expected.add(("secret", "config.py", 2))
    expected.add(("vulnerable-dependency", "requirements.txt", 1))   # flask==2.0.0
    return {"expected": expected, "safe_lines": safe}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="run the local claude CLI review (slow)")
    ap.add_argument("--out", default=str(ROOT / "data" / "eval"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    obs.configure(out / "logs")

    with tempfile.TemporaryDirectory() as td:
        repo = Path(td) / "vulnapp"
        gt = prepare(repo)
        db = Database(out / "eval.db")
        scanners = default_scanners()
        t0 = time.monotonic()
        scan = scan_and_store(db, ScanTarget("local:vulnapp-eval", repo, "eval"), scanners)
        rows = db.list_findings("local:vulnapp-eval")
        llm_times = []
        if a.llm:
            for r in rows:
                if r["category"] == "vulnerable-dependency":
                    continue        # OSV advisories: LLM adds little; validated by usage analysis
                t = time.monotonic()
                try:
                    review_finding(db, r["id"])
                except Exception as e:   # recorded in DB; keep evaluating
                    print(f"review {r['id']} failed: {e}", file=sys.stderr)
                llm_times.append(time.monotonic() - t)
        for r in rows:
            validate_finding(db, r["id"], scanners, out / "evidence")
        total = time.monotonic() - t0

        rows = db.list_findings("local:vulnapp-eval")
        det = {(r["category"], r["file"], r["line"]) for r in rows}
        dep_rows = [r for r in rows if r["category"] == "vulnerable-dependency"]
        code_det = {d for d in det if d[0] != "vulnerable-dependency"}
        code_exp = {e for e in gt["expected"] if e[0] != "vulnerable-dependency"}
        tp = code_det & code_exp
        fp_det = code_det - code_exp
        dep_hit = any(r["file"] == "requirements.txt" and r["line"] == 1 for r in dep_rows)

        verdicts = {}
        for r in rows:
            v = db.latest_verdict(r["fingerprint"])
            verdicts[r["id"]] = {"category": r["category"], "loc": f"{r['file']}:{r['line']}",
                                 "is_true_vuln": (r["category"], r["file"], r["line"]) in gt["expected"]
                                 or (r["category"] == "vulnerable-dependency"),
                                 "verdict": v["verdict"], "basis": v["basis"], "score": v["confidence_score"]}
        wrong_confirm = [k for k, v in verdicts.items() if v["verdict"] == "CONFIRMED" and not v["is_true_vuln"]]
        wrong_fp = [k for k, v in verdicts.items() if v["verdict"] == "FALSE_POSITIVE" and v["is_true_vuln"]]

        report = {
            "scan": {k: scan[k] for k in ("findings", "new", "duration_ms", "scanners_run")},
            "detection_code_and_secrets": {
                "expected": len(code_exp), "true_positives": len(tp), "false_positives": len(fp_det),
                "precision": round(len(tp) / len(code_det), 3) if code_det else None,
                "recall": round(len(tp) / len(code_exp), 3),
                "missed": sorted(code_exp - code_det), "fp_on_safe_traps": sorted(
                    d for d in code_det if d[1] == "app.py" and d[2] in gt["safe_lines"]),
            },
            "detection_dependencies": {"vulnerable_pin_found": dep_hit, "advisories": len(dep_rows)},
            "verdicts": verdicts,
            "verdict_errors": {"confirmed_but_not_vuln": wrong_confirm, "false_positive_but_vuln": wrong_fp},
            "metrics": db.metrics("local:vulnapp-eval"),
            "timing": {"total_s": round(total, 1),
                       "llm_reviews": len(llm_times),
                       "llm_avg_s": round(sum(llm_times) / len(llm_times), 1) if llm_times else None},
        }
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
