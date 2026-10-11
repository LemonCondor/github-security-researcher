#!/usr/bin/env python3
"""Ranked Go bug triage for a local checkout, with a cache and a registry of already-examined sites.

  scripts/hunt.py PATH [--top N] [--all] [--json]

- Cache: data/hunt_cache/<sha256(path|HEAD|dirty-diff|detector)>.json — reused only when the commit, the working
  tree diff and the detector version are identical (any change invalidates it).
- Ranking: candidates are sorted by detector prior; bug-family signals (late length guard, ignored acquire +
  deferred release, nil checked before err) carry FAMILY_CONFIDENCE and come first. FALSE_POSITIVE is hidden.
- Registry (data/bug_registry.json): sites already examined (confirmed, duplicate, rejected) are marked so they are
  not re-triaged. Matching is by repo remote + file + function + category, never by line only.
Read-only on the checkout; no network.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
CACHE = ROOT / "data" / "hunt_cache"
REGISTRY = ROOT / "data" / "bug_registry.json"


def _git(path: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def repo_identity(path: Path) -> str:
    url = _git(path, "config", "--get", "remote.origin.url")
    if url.startswith(("http", "git@")):
        return url.removesuffix(".git").split("github.com")[-1].lstrip(":/").lower()
    return path.resolve().name.lower()


def registry() -> list[dict]:
    return json.loads(REGISTRY.read_text())["entries"] if REGISTRY.exists() else []


def known(entries: list[dict], repo: str, c: dict) -> dict | None:
    for e in entries:
        if e["repo"].lower() == repo and e["file"] == c["file"] and e["function"] == c["function"] \
                and e["category"] == c["category"]:
            return e
    return None


def detect(path: Path) -> tuple[list[dict], bool, float]:
    from github_security.bugs.go_detectors import detect_go_report
    from github_security.bugs.storage import DETECTOR
    head = _git(path, "rev-parse", "HEAD") or "nogit"
    diff = _git(path, "diff", "HEAD") if head != "nogit" else ""
    key = hashlib.sha256(f"{path.resolve()}|{head}|{hashlib.sha256(diff.encode()).hexdigest()}|{DETECTOR}"
                         .encode()).hexdigest()[:24]
    f = CACHE / f"{key}.json"
    if f.exists():
        return json.loads(f.read_text()), True, 0.0
    t = time.monotonic()
    cands = [c.to_dict() for c in detect_go_report(path).candidates]
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(cands))
    return cands, False, time.monotonic() - t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--all", action="store_true", help="also list already-examined sites")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    path = Path(a.path)
    cands, cached, secs = detect(path)
    repo, entries = repo_identity(path), registry()
    rows = []
    for c in cands:
        if c["status"] == "FALSE_POSITIVE":
            continue
        k = known(entries, repo, c)
        if k and not a.all:
            continue
        rows.append({**c, "registry": k["outcome"] if k else None})
    rows.sort(key=lambda c: (-c["confidence"], c["status"] != "BUG_CANDIDATE", c["file"], c["line"]))
    if a.json:
        print(json.dumps(rows[:a.top], indent=1))
        return 0
    print(f"{repo} @ {_git(path, 'rev-parse', '--short=12', 'HEAD')}: {len(cands)} candidates, "
          f"{len(rows)} to triage ({'cache hit' if cached else f'detected in {secs:.1f}s'})")
    for c in rows[:a.top]:
        tag = f" [{c['registry']}]" if c["registry"] else ""
        print(f"  {c['confidence']:.1f} {c['status']:<13} {c['category']:<22} {c['file']}:{c['line']} "
              f"{c['function']}{tag}\n        {c['suspicion'][:150]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
