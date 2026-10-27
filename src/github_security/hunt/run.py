"""`gsr hunt` orchestrator: gates -> targets -> hunter -> proof -> duplicate -> fixer -> red/green -> skeptic -> branch.

One Claude process at a time. Nothing is pushed or published; READY results are local branches."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..security.secrets import redact_obj
from ..ai.reviewer import ReviewError, claude_cli_runner
from .agent import claude_agent_runner, fix_allow, hunt_allow
from .fix import commit_branch, verify_fix
from .gates import check_gates
from .lang import Toolchain, detect_lang, repro_cmd, test_cmd
from .model import Finding, Result, Target
from .proof import add_worktree, find_duplicate, parse_findings, prove, remove_worktree
from .prompts import FIX_SCHEMA, FIX_SYSTEM, HUNT_SCHEMA, HUNT_SYSTEM, SKEPTIC_SCHEMA, SKEPTIC_SYSTEM, fix_prompt, \
    hunt_prompt, skeptic_prompt
from .targeting import rank_files


@dataclass
class HuntOptions:
    files: int = 8
    budget_min: int = 20
    lang: str = "auto"
    toolchain: Toolchain = field(default_factory=Toolchain)
    author: str = "LemonCondor <yomgui12@outlook.com>"
    model: str | None = None


def _contributing(repo: Path) -> str:
    for name in ("CONTRIBUTING.md", ".github/CONTRIBUTING.md", "CONTRIBUTING.rst"):
        if (repo / name).is_file():
            return (repo / name).read_text(errors="replace")
    return ""


def _run_cmd(lang: str, t: Target, tc: Toolchain) -> str:
    path = {"py": "repro/gsr_repro.py", "js": "repro/gsr_repro.mjs"}.get(lang) or \
        str(Path(t.path).parent / "gsr_repro_test.go")
    return " ".join(repro_cmd(lang, path, tc))


def _branch(f: Finding) -> str:
    return "fix/gsr-" + (re.sub(r"[^a-z0-9]+", "-", f.function.lower()).strip("-")[:40] or "bug")


def _process(slug, repo, lang, t: Target, f: Finding, hunt_dir, work, opts, agent, skeptic, dup) -> Result:
    tc = opts.toolchain
    proved, out = prove(repo, f, lang, tc, hunt_dir, work)
    if not proved:
        return Result("REJECTED_NO_REPRO", t.path, f, out)
    url = dup(slug, f)
    if url:
        return Result("DUPLICATE", t.path, f, url)
    fix_dir = add_worktree(repo, work / f"fix-{_branch(f).split('/')[-1]}")
    try:
        (fix_dir / f.repro_path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(hunt_dir / f.repro_path, fix_dir / f.repro_path)
        hint = " ".join(test_cmd(lang, "<test file>", repo, tc))
        try:
            raw = agent(FIX_SYSTEM, fix_prompt(f, lang, test_cmd_hint=hint), FIX_SCHEMA, cwd=fix_dir, allow=fix_allow(tc),
                        model=opts.model, timeout=opts.budget_min * 60)
        except ReviewError as e:
            return Result("ERROR", t.path, f, f"fixer: {e}")
        tests = [p for p in raw.get("test_files", []) if isinstance(p, str)]
        ok, why = verify_fix(fix_dir, tests, lang, tc)
        if not ok:
            return Result("REJECTED_FIX", t.path, f, why)
        subprocess.run(["git", "-C", str(fix_dir), "add", "-N", "--", ".", ":(exclude)repro",
                        ":(exclude)**/gsr_repro_test.go"], capture_output=True, text=True)
        diff = subprocess.run(["git", "-C", str(fix_dir), "diff", "HEAD"], capture_output=True, text=True).stdout
        try:
            verdict = skeptic(SKEPTIC_SYSTEM, skeptic_prompt(f, diff, _contributing(repo)), SKEPTIC_SCHEMA,
                              model=opts.model)
        except ReviewError as e:
            return Result("ERROR", t.path, f, f"skeptic: {e}")
        if verdict.get("verdict") != "KEEP":
            return Result("DROPPED_SKEPTIC", t.path, f, str(verdict.get("reason", "")))
        branch = _branch(f)
        sha = commit_branch(fix_dir, branch, f"Fix {f.function}: {f.hypothesis}"[:72], opts.author)
        return Result("READY", t.path, f, why, branch=branch, commit=sha)
    finally:
        remove_worktree(repo, fix_dir)


def hunt(slug: str, repo: Path, opts: HuntOptions, *, out_dir: Path, agent=claude_agent_runner,
         skeptic=claude_cli_runner, gate=check_gates, dup=find_duplicate) -> tuple[list[Result], Path]:
    results: list[Result] = []
    try:
        ok, why = gate(slug)
    except Exception as e:  # noqa: BLE001
        ok, why = False, f"gate error: {e}"
    if not ok:
        results.append(Result("GATED", detail=why))
    else:
        lang = detect_lang(repo) if opts.lang == "auto" else opts.lang
        work = Path(tempfile.mkdtemp(prefix="gsr-hunt-", dir="/tmp"))
        try:
            for i, t in enumerate(rank_files(repo, lang, opts.files)):
                hunt_dir = None
                try:
                    hunt_dir = add_worktree(repo, work / f"hunt-{i}")
                    raw = agent(HUNT_SYSTEM, hunt_prompt(t, lang, run_cmd=_run_cmd(lang, t, opts.toolchain)), HUNT_SCHEMA, cwd=hunt_dir,
                                allow=hunt_allow(opts.toolchain), model=opts.model, timeout=opts.budget_min * 60)
                    found = parse_findings(raw)
                    if not found:
                        results.append(Result("NO_FINDINGS", t.path))
                    for f in found:
                        try:
                            results.append(_process(slug, repo, lang, t, f, hunt_dir, work, opts, agent, skeptic,
                                                    dup))
                        except Exception as e:  # noqa: BLE001
                            results.append(Result("ERROR", t.path, f, f"{type(e).__name__}: {e}"))
                except Exception as e:  # noqa: BLE001
                    results.append(Result("ERROR", t.path, detail=f"{type(e).__name__}: {e}"))
                finally:
                    if hunt_dir is not None:
                        remove_worktree(repo, hunt_dir)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    report = out_dir / f"{slug.replace('/', '__')}-{stamp}.json"
    report.write_text(json.dumps({"repo": slug, "results": [redact_obj(r.to_dict()) for r in results]}, indent=2))
    return results, report
