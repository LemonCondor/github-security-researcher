"""A fix is accepted only if its new tests fail without the source change and pass with it (decided by code)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .lang import Toolchain, test_cmd, run

_NOT_SOURCE = re.compile(r"(^|/)(tests?|__tests__|repro|changes|changelog\.d)/|(^|/)test_[^/]*\.py$|_test\.go$|"
                         r"\.(test|spec)\.[jt]sx?$|\.(rst|md|txt)$")
_EXCLUDE = [":(exclude)repro", ":(exclude)**/gsr_repro_test.go", ":(exclude,glob)**/__pycache__/**", ":(exclude,glob)**/*.pyc",
            ":(exclude,glob)**/.pytest_cache/**", ":(exclude,glob)**/node_modules/**"]


def _git(d: Path, *a: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(d), *a], capture_output=True, text=True)


def _run_tests(d: Path, test_files: list[str], lang: str, tc: Toolchain) -> tuple[bool, str]:
    for t in test_files:
        rc, out = run(test_cmd(lang, t, d, tc), d)
        if rc != 0:
            return False, out[-1500:]
    return True, ""


def verify_fix(fix_dir: Path, test_files: list[str], lang: str, tc: Toolchain) -> tuple[bool, str]:
    if not test_files:
        return False, "no regression test"
    ok, out = _run_tests(fix_dir, test_files, lang, tc)
    if not ok:
        return False, "tests fail with the fix:\n" + out
    sources = [p for p in _git(fix_dir, "diff", "--name-only", "HEAD").stdout.split() if not _NOT_SOURCE.search(p)]
    if not sources:
        return False, "no source change"
    if _git(fix_dir, "stash", "push", "-q", "--", *sources).returncode != 0:
        return False, "could not stash the fix"
    try:
        green_without_fix, _ = _run_tests(fix_dir, test_files, lang, tc)
    finally:
        _git(fix_dir, "stash", "pop", "-q")
    return (False, "new test passes without the fix") if green_without_fix else (True, "red without fix, green with")


def commit_branch(fix_dir: Path, branch: str, message: str, author: str) -> str:
    name, email = re.match(r"(.+?)\s*<(.+)>", author).groups()
    _git(fix_dir, "checkout", "-q", "-b", branch)
    _git(fix_dir, "add", "-A", "--", ".", *_EXCLUDE)
    _git(fix_dir, "-c", f"user.name={name}", "-c", f"user.email={email}", "commit", "-q", "-m", message)
    return _git(fix_dir, "rev-parse", "HEAD").stdout.strip()
