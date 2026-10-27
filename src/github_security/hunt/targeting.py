"""Pick the source files most likely to hide a user-facing logic bug: risky vocabulary + past fix churn."""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

from .lang import EXTS
from .model import Target

RISK = re.compile(r"parse|cache|key|date|time|tz|round|decimal|split|encode|decode|serial|merge|range|offset|"
                  r"format|convert", re.I)
SKIP = re.compile(r"(^|/)(tests?|testing|vendor|node_modules|dist|build|docs?|examples?|__tests__|third_party)/|"
                  r"_test\.go$|(^|/)test_[^/]*\.py$|\.(test|spec)\.[jt]sx?$|_pb2\.py$|\.d\.ts$|\.min\.js$")


def _git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""


def _fix_churn(repo: Path) -> Counter:
    out = _git(repo, "log", "--since=2.years", "-i", "--grep=fix", "--name-only", "--format=")
    return Counter(line for line in out.splitlines() if line)


def rank_files(repo: Path, lang: str, n: int = 8) -> list[Target]:
    churn = _fix_churn(repo)
    ranked = []
    for path in _git(repo, "ls-files").splitlines():
        if not path.endswith(EXTS[lang]) or SKIP.search(path):
            continue
        try:
            text = (repo / path).read_text(errors="replace")[:200_000]
        except OSError:
            continue
        lines = text.count("\n")
        if lines < 30 or lines > 3000:
            continue
        hits, fixes = len(RISK.findall(text)), churn[path]
        score = min(hits, 50) / 50 * 2 + min(fixes, 20) / 20 * 3
        if score:
            ranked.append(Target(path, round(score, 3), [f"risk-words={hits}", f"fix-commits={fixes}"]))
    ranked.sort(key=lambda t: -t.score)
    return ranked[:n]
