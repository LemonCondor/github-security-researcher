"""Deterministic proof: a finding counts only if its repro fails on a CLEAN checkout and no open issue/PR covers it."""
from __future__ import annotations

import math
import re
import shutil
import subprocess
import uuid
from pathlib import Path, PurePosixPath

from .lang import Toolchain, repro_cmd, run
from .model import Finding

_ASSERT = {"py": re.compile(r"AssertionError"), "go": re.compile(r"--- FAIL: TestGsrRepro"),
           "js": re.compile(r"AssertionError|Error \[ERR_ASSERTION\]|GSR_BUG")}
_BROKEN = re.compile(r"ModuleNotFoundError|ImportError|SyntaxError|IndentationError|NameError|"
                     r"ERR_MODULE_NOT_FOUND|Cannot find module|build failed|\[setup failed\]|undefined: ")

_STR = ("file", "function", "hypothesis", "realistic_input", "expected", "actual", "repro_path", "user_impact")


def parse_findings(raw: dict) -> list[Finding]:
    out = []
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
        return []
    for item in raw["findings"][:3]:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k] for k in _STR):
            continue
        conf = item.get("confidence")
        p = PurePosixPath(item["repro_path"])
        if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not math.isfinite(conf) \
                or not 0 <= conf <= 1 or "\\" in item["repro_path"] or p.is_absolute() or ".." in p.parts:
            continue
        out.append(Finding(**{k: item[k] for k in _STR}, confidence=float(conf)))
    return out


def add_worktree(repo: Path, dest: Path) -> Path:
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-q", "--detach", str(dest), "HEAD"], check=True,
                   capture_output=True)
    return dest


def remove_worktree(repo: Path, dest: Path) -> None:
    subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(dest)], capture_output=True)
    shutil.rmtree(dest, ignore_errors=True)


def prove(repo: Path, f: Finding, lang: str, tc: Toolchain, src_dir: Path, work: Path) -> tuple[bool, str]:
    src = src_dir / f.repro_path
    if src.is_symlink():
        return False, "repro is a symlink"
    if not src.is_file():
        return False, "repro missing"
    clean = work / f"proof-{uuid.uuid4().hex[:12]}"
    try:
        add_worktree(repo, clean)
        (clean / f.repro_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, clean / f.repro_path)
        rc, out = run(repro_cmd(lang, f.repro_path, tc), clean)
    except subprocess.CalledProcessError:
        return False, "worktree failed"
    finally:
        remove_worktree(repo, clean)
    proved = rc not in (0, 124, 127) and bool(_ASSERT[lang].search(out)) and not _BROKEN.search(out)
    return proved, out[-1500:]


def _gh_search(q: str) -> str | None:
    try:
        p = subprocess.run(["gh", "api", "-X", "GET", "search/issues", "-f", f"q={q}", "-f", "per_page=1", "--jq",
                            ".items[0].html_url // empty"], capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "SEARCH_FAILED"
    if p.returncode != 0:
        return "SEARCH_FAILED"
    return p.stdout.strip() or None


def find_duplicate(slug: str, f: Finding, search=_gh_search) -> str | None:
    """Return a duplicate URL, or "SEARCH_FAILED" if the search errored (fail closed: any non-None = treat as duplicate)."""
    return search(f"repo:{slug} is:open {f.function} in:title,body")
