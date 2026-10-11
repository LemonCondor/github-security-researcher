#!/usr/bin/env python3
"""One-command duplicate / already-fixed check before preparing an upstream fix (read-only GitHub API via gh).

  scripts/dupcheck.py OWNER/REPO FILE [--pattern TEXT] [--terms "a b" ...] [--branch BRANCH]

Reports, in one pass:
  1. whether TEXT (the buggy line) is still present in FILE on the default (or given) branch;
  2. open PRs touching FILE (diff scanned for TEXT when given);
  3. issues / PRs matching each search term (open and closed).
Exit code 0 = no blocker found, 1 = possible duplicate or already fixed (read the report), 2 = API error.
Only a subset of PRs/issues is examined (GitHub search + up to 100 open PRs): absence is not proof.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys


def gh(*args: str):
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:200])
    return json.loads(r.stdout) if r.stdout.strip() else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("repo")
    ap.add_argument("file")
    ap.add_argument("--pattern", help="exact text of the buggy line (checked on the branch and in open PR diffs)")
    ap.add_argument("--terms", nargs="*", default=[], help="search phrases for issues/PRs")
    ap.add_argument("--branch")
    a = ap.parse_args()
    blockers = []
    try:
        branch = a.branch or gh("api", f"repos/{a.repo}")["default_branch"]
        if a.pattern:
            body = gh("api", f"repos/{a.repo}/contents/{a.file}?ref={branch}")
            text = base64.b64decode(body["content"]).decode(errors="replace")
            present = a.pattern in text
            print(f"[branch {branch}] buggy text {'STILL PRESENT' if present else 'NOT FOUND (fixed or moved?)'}")
            if not present:
                blockers.append("pattern not on branch")
        prs = gh("pr", "list", "-R", a.repo, "--state", "open", "--limit", "100", "--json", "number,title,files")
        touching = [p for p in prs if any(f["path"] == a.file for f in p.get("files") or [])]
        for p in touching:
            hit = ""
            if a.pattern:
                diff = subprocess.run(["gh", "pr", "diff", str(p["number"]), "-R", a.repo],
                                      capture_output=True, text=True).stdout
                minus = [ln for ln in diff.splitlines() if ln.startswith("-") and a.pattern.strip() in ln]
                hit = " — REMOVES the buggy line" if minus else ""
                if minus:
                    blockers.append(f"open PR #{p['number']} removes the line")
            print(f"[open PR touching file] #{p['number']} {p['title']}{hit}")
        print(f"[open PRs scanned] {len(prs)} (touching {a.file}: {len(touching)})")
        for term in a.terms:
            for kind in ("issues", "prs"):
                res = gh("search", kind, "--repo", a.repo, term, "--limit", "8", "--json", "number,title,state")
                for r in res or []:
                    print(f"[search {kind} '{term}'] #{r['number']} {r['state']} {r['title']}")
    except RuntimeError as e:
        print(f"API error: {e}")
        return 2
    print("RESULT:", "possible blocker: " + "; ".join(blockers) if blockers else "no blocker found "
          "(search results above still need a human read)")
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
