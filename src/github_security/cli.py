"""github-sec command line."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from . import config as cfg
from . import observability as obs
from .github import client, repositories
from .security.policy import PolicyViolation, resolve_target


def _tool_version(cmd: list[str]) -> str:
    exe = shutil.which(cmd[0])
    if not exe:
        return "missing"
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except Exception as e:  # noqa: BLE001
        return f"error: {e}"


def cmd_status(settings, args) -> int:
    auth = client.auth_status() if shutil.which("gh") else {"authenticated": False}
    p = settings.policies
    print(json.dumps({
        "github": auth,
        "tools": {
            "git": _tool_version(["git", "--version"]),
            "gh": _tool_version(["gh", "--version"]),
            "semgrep": _tool_version(["semgrep", "--version"]),
            "gitleaks": _tool_version(["gitleaks", "version"]),
            "pip-audit": _tool_version(["pip-audit", "--version"]),
            "claude": _tool_version(["claude", "--version"]),
        },
        "scope": {"targets": [t.slug for t in settings.targets], "blocked": sorted(settings.blocked)},
        "policies": {"allow_pr_creation": p.allow_pr_creation,
                     "allow_issue_creation": p.allow_issue_creation,
                     "allow_comment_creation": p.allow_comment_creation},
    }, indent=2))
    return 0


def cmd_config(settings, args) -> int:
    print(json.dumps({
        "root": str(settings.root), "data_dir": str(settings.data_dir),
        "workspace": str(settings.workspace),
        "targets": [t.__dict__ for t in settings.targets],
        "blocked_targets": sorted(settings.blocked),
        "policies": settings.policies.__dict__,
    }, indent=2))
    return 0


def cmd_check_target(settings, args) -> int:
    """Read-only metadata lookup to help decide whether a repo may be added to scope."""
    owner, _, repo = args.repo.partition("/")
    cfg._validate_name(owner, "owner"), cfg._validate_name(repo, "repository")
    meta = client.repo_metadata(owner, repo)
    print(json.dumps({
        **{k: meta[k] for k in ("full_name", "private", "archived", "fork", "default_branch", "language")},
        "size_mb": round(meta["size_kb"] / 1024, 1),
        "security_policy": client.security_policy_url(owner, repo),
        "private_vulnerability_reporting": client.private_vulnerability_reporting(owner, repo),
        "in_scope": any(t.slug == args.repo.lower() for t in settings.targets),
    }, indent=2))
    return 0


def cmd_clone(settings, args) -> int:
    target = resolve_target(settings, args.repo)
    local = repositories.clone_or_update(settings, target)
    print(json.dumps({"repository": local.slug, "path": str(local.path),
                      "branch": local.branch, "commit": local.commit}, indent=2))
    return 0


def _scanners(settings):
    from .scanner.runner import default_scanners
    from .scanner.semgrep import INTERNAL_RULES
    p = settings.policies
    return default_scanners([str(INTERNAL_RULES), *p.semgrep_registry_packs], list(p.scanners_enabled))


def _db(settings):
    from .storage.database import Database
    return Database(settings.data_dir / "gsr.db")


def _scan_target(settings, args):
    """OWNER/REPO (clone/update, pinned commit enforced) or --path DIR. A path inside the workspace checkout of a
    configured target keeps that target's identity (slug) and must sit at its pinned commit."""
    from pathlib import Path

    from .scanner.base import ScanTarget

    if args.path:
        root = Path(args.path).resolve()
        if not root.is_dir():
            raise cfg.ConfigError(f"not a directory: {root}")
        try:
            commit = repositories.git("rev-parse", "HEAD", cwd=root)
        except repositories.CloneError:
            commit = "workdir"
        slug = f"local:{root.name}"
        try:
            rel = root.relative_to((settings.workspace / "repos").resolve()).parts
        except ValueError:
            rel = ()
        if len(rel) == 2:
            t = resolve_target(settings, "/".join(rel))
            if t.commit and commit != t.commit:
                raise PolicyViolation(f"{t.slug}: checkout is {commit}, expected pinned {t.commit}")
            slug = t.slug
        return ScanTarget(slug=slug, path=root, commit=commit)
    if not args.repo:
        raise cfg.ConfigError("give OWNER/REPO or --path DIR")
    local = repositories.clone_or_update(settings, resolve_target(settings, args.repo))
    return ScanTarget(slug=local.slug, path=local.path, commit=local.commit)


def cmd_scan(settings, args) -> int:
    """Scan only. Never creates PRs, issues or comments."""
    from .pipeline import detect_and_store_bugs, scan_and_store

    target = _scan_target(settings, args)
    db = _db(settings)
    summary = scan_and_store(db, target, _scanners(settings))
    if args.with_bugs:
        summary = {"security": summary, "bugs": detect_and_store_bugs(db, target)}
    print(json.dumps(summary, indent=2))
    for f in db.list_findings(target.slug):
        print(f"  [{f['severity']:>8}] {f['id']} {f['category']:<26} {f['file']}:{f['line']}  "
              f"({f['scanner']}:{f['rule']}) status={f['status']}")
    return 0


def cmd_findings(settings, args) -> int:
    db = _db(settings)
    for f in db.list_findings(args.repo, None if args.all else "open"):
        v = db.latest_verdict(f["fingerprint"])
        verdict = f"{v['verdict']}({v['confidence_score']:.2f})" if v else "-"
        print(f"[{f['severity']:>8}] {f['id']} {f['repository']} {f['category']:<26} "
              f"{f['file']}:{f['line']} {f['state']}/{f['status']} verdict={verdict}")
    return 0


def render_finding(rep: dict) -> str:
    """Human-readable view of the separated layers of one finding."""
    d = rep["detection"]
    out = [f"Finding {rep['id']}  [{rep['repository']}]  state={rep['state']} status={rep['status']}", "",
           "== Detection (scanner_result)",
           f"  {d['scanner']}:{d['rule']}  category={d['category']}  severity={d['severity']}  "
           f"scanner_confidence={d['scanner_confidence']}",
           f"  {d['file']}:{d['line']}  commit={d['commit'][:12]}  source={d['source']} sink={d['sink']}",
           f"  {d['description'][:200]}", "",
           "== LLM analysis (contextual_analysis, ADVISORY)"]
    llm = rep.get("contextual_analysis")
    if llm:
        out += [f"  proposed={llm.get('verdict')} conf={llm.get('confidence')} severity={llm.get('severity')} "
                f"injection_suspected={llm.get('injection_suspected')}",
                f"  {str(llm.get('reasoning_summary', ''))[:400]}"]
    else:
        out.append("  (none)")
    out += ["", "== Evidence"]
    for e in rep.get("evidence") or []:
        side = "SUPPORTS" if e["supports"] else "CONTRADICTS" if e["contradicts"] else "neutral"
        out.append(f"  - {e['type']:<18} {side:<11} {e['strength']:<8} {e['status']:<10} "
                   f"{'independent' if e['independent'] else 'not-independent'}  ({e['source']})")
        out.append(f"      {e['description'][:160]}")
    if not rep.get("evidence"):
        out.append("  (no decision yet)")
    out += ["", "== Confidence", f"  confidence_score = {rep.get('confidence_score')}  "
            "(separate from the verdict; never used as a threshold)"]
    out += ["", "== Final verdict", f"  proposed_verdict (LLM) = {rep.get('proposed_verdict')}",
            f"  final_verdict          = {rep.get('final_verdict') or (rep.get('verdict') or {}).get('verdict')}"]
    r = rep.get("decision_reason")
    out += ["", "== Decision reason"]
    if r:
        out.append(f"  rule: {r['rule']} - {r['summary']}")
        for ra in r["rules_applied"]:
            out.append(f"    [{'x' if ra['matched'] else ' '}] {ra['rule']:<28} -> {ra['outcome']:<14} {ra['why']}")
        for m in r["missing_evidence"]:
            out.append(f"  missing: {m}")
        out.append(f"  executed_target_code: {r['executed_target_code']}")
    out += ["", "== Human review required",
            f"  {rep.get('human_review_required')}" + (f"  ({'; '.join(r['human_review_reasons'])})" if r else "")]
    if rep.get("regression_drafts"):
        out += ["", "== Regression test drafts (UNEXECUTED, not evidence)"] + [f"  {x['path']}" for x in rep["regression_drafts"]]
    return "\n".join(out)


def cmd_finding(settings, args) -> int:
    from .pipeline import finding_report
    db = _db(settings)
    rep = finding_report(db, args.id)
    if rep is None:
        raise cfg.ConfigError(f"unknown finding {args.id}")
    print(json.dumps(rep, indent=2, default=str) if args.json else render_finding(rep))
    return 0


def cmd_review_queue(settings, args) -> int:
    db = _db(settings)
    rows = db.human_review_queue(args.repo)
    for r in rows:
        print(f"{r['id']} {r['final_verdict']:<14} score={r['confidence_score']:.2f} {r['rule']:<28} "
              f"{r['repository']} {r['category']} {r['file']}:{r['line']}")
    print(f"{len(rows)} finding(s) awaiting human review (nothing is disclosed automatically)")
    return 0


def cmd_metrics(settings, args) -> int:
    print(json.dumps(_db(settings).metrics(args.repo), indent=2))
    return 0


def _select(db, args):
    if getattr(args, "id", None):
        return [args.id]
    rows = db.list_findings(args.repo)
    return [r["id"] for r in rows][: args.limit]


def cmd_review(settings, args) -> int:
    from .ai.reviewer import ReviewError
    from .pipeline import review_finding
    db = _db(settings)
    rc = 0
    for fid in _select(db, args):
        try:
            out = review_finding(db, fid, model=settings.policies.llm_model)
            print(f"{fid}: {out['verdict']} conf={out['confidence']:.2f} sev={out['severity']} "
                  f"human_review={out['requires_human_review']} warnings={out['warnings']}", flush=True)
        except (ReviewError, FileNotFoundError) as e:
            print(f"{fid}: ERROR {e}", file=sys.stderr)
            rc = 1
    return rc


def cmd_validate(settings, args) -> int:
    from .pipeline import validate_finding
    db = _db(settings)
    for fid in _select(db, args):
        r = validate_finding(db, fid, _scanners(settings), settings.data_dir / "evidence")
        print(f"{fid}: {r['verdict']} rule={r['rule']} confidence_score={r['confidence_score']:.2f} "
              f"proposed(LLM)={r['proposed_verdict']} human_review={r['human_review_required']}")
        for st in r["steps"]:
            print(f"    {st[0]:<30} {st[1]:<15} {st[2]}/{st[3]}")
    return 0


def cmd_analyze(settings, args) -> int:
    """Full pipeline per finding; the LLM is only called when static evidence cannot decide."""
    from .ai.reviewer import ReviewError
    from .pipeline import analyze_finding
    db = _db(settings)
    rc = skipped = called = 0
    for fid in _select(db, args):
        try:
            r = analyze_finding(db, fid, _scanners(settings), settings.data_dir / "evidence",
                                model=settings.policies.llm_model)
        except (ReviewError, FileNotFoundError) as e:
            print(f"{fid}: ERROR {e}", file=sys.stderr, flush=True)
            rc = 1
            continue
        skipped += r["llm_skipped"]
        called += not r["llm_skipped"]
        print(f"{fid}: {r['verdict']} rule={r['rule']} confidence_score={r['confidence_score']:.2f} "
              f"llm={'skipped' if r['llm_skipped'] else 'called'} proposed(LLM)={r['proposed_verdict']}", flush=True)
    print(f"LLM calls: {called} made, {skipped} avoided by static triage", flush=True)
    return rc


def cmd_draft_test(settings, args) -> int:
    from .pipeline import draft_regression_test
    r = draft_regression_test(_db(settings), args.id, settings.data_dir / "evidence",
                              model=settings.policies.llm_model)
    print(f"{r['id']}: regression test DRAFT written ({r['status']}, never executed, not evidence)\n  {r['path']}")
    return 0


def _bug_line(b) -> str:
    return (f"  {b['id']} {b['status']:<14} {b['category']:<18} {b['file']}:{b['line']}  {b['function']}"
            f"  [{b['state']}]")


def cmd_bugs(settings, args) -> int:
    """Ordinary bug candidates (Go, static, nothing executed). Separate from security findings. Never opens PRs."""
    from .bugs.storage import BugStore
    from .pipeline import detect_and_store_bugs, review_bug

    target = _scan_target(settings, args)
    db = _db(settings)
    summary = detect_and_store_bugs(db, target)
    store = BugStore(db)
    reviews = []
    if args.review:
        for b in store.actionable(target.slug)[:args.review]:
            if b["llm_review"] is None and b["status"] == "BUG_CANDIDATE":
                reviews.append(review_bug(db, b["id"], model=settings.policies.llm_model))
    rows = [b for b in store.list(target.slug) if b["last_commit"] == target.commit]
    if args.json:
        print(json.dumps({**summary, "llm_reviews": len(reviews), "candidates": [
            {k: b[k] for k in ("id", "fingerprint", "status", "status_reason", "category", "rule", "function",
                               "file", "line", "suspicion", "confidence", "state")} |
            {"negative_evidence": json.loads(b["negative_evidence"]), "ambiguity": json.loads(b["ambiguity"])}
            for b in rows]}, indent=2))
        return 0
    print(f"{target.slug} @ {target.commit}: {summary['candidates']} candidate(s) in {summary['duration_ms']} ms")
    print(f"  by category: {summary['by_category']}\n  by status:   {summary['by_status']}\n"
          f"  dedup:       {summary['dedup']}" +
          (f"\n  gone:        {summary['gone_reasons']} (disappearance is not a fix)" if summary['gone_reasons'] else "")
          + (f"\n  llm reviews: {len(reviews)}" if args.review else ""))
    for b in rows:
        print(_bug_line(b))
        print(f"      {b['suspicion']}")
    print("Candidates are suspicions, not confirmed bugs. Nothing is published.")
    return 0


def cmd_bug(settings, args) -> int:
    from .bugs.reproduction import plan_reproduction, pr_gate
    from .bugs.storage import BugStore

    store = BugStore(_db(settings))
    b = store.get(args.id)
    if b is None:
        raise cfg.ConfigError(f"unknown bug {args.id}")
    task = plan_reproduction(store.candidate_from_row(b))
    target = next((t for t in settings.targets if t.slug == b["repository"]), None)
    rep = {**{k: b[k] for k in b.keys() if k not in ("repository_id",)},
           "reproduction_task": task.to_dict() if task else None,
           "pr_gate_unmet": pr_gate(b, settings, target),
           "events": [dict(e) for e in store.events(b["fingerprint"])]}
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return 0
    print(f"{b['id']} {b['status']} ({b['status_reason']})\n{b['repository']} @ {b['last_commit']} "
          f"{b['file']}:{b['line']} {b['function']} [{b['category']}]\n\n{b['suspicion']}\n\n{b['snippet']}")
    print(f"\nnegative evidence: {b['negative_evidence']}\nambiguity: {b['ambiguity']}")
    if b["state"] == "gone":
        print(f"state: gone ({b['gone_reason']}) - no longer produced; this is NOT evidence of a fix")
    print(f"lifecycle: validation={b['validation_state']} reproduction={b['reproduction_state']} "
          f"test={b['regression_test_state']} patch={b['patch_state']} pr={b['pr_state']}")
    print("reproduction task: " + (json.dumps(task.to_dict(), indent=2) if task else "none (not plannable)"))
    print("PR gate unmet:\n  - " + "\n  - ".join(rep["pr_gate_unmet"]))
    return 0


def cmd_bug_metrics(settings, args) -> int:
    from .bugs.storage import BugStore
    print(json.dumps(BugStore(_db(settings)).metrics(args.repo), indent=2))
    return 0


def cmd_bug_reject(settings, args) -> int:
    """Reasoned human rejection of one candidate (trace in bug_events). Not a fix, not a FALSE_POSITIVE status."""
    from .bugs.storage import BugStore, DecisionError
    try:
        d = BugStore(_db(settings)).reject(args.repo, args.id, args.reason)
    except DecisionError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"{d['id']} {d['repository']} @ {d['commit']} {d['file']}:{d['line']}: validation_state=REJECTED "
          f"(human decision; status {d['status']} unchanged; observations kept)")
    return 0


def cmd_bug_pr(settings, args) -> int:
    """Record the real outcome of a PR that fixes a stored candidate (written by a human; nothing is sent)."""
    import re

    from .bugs.storage import BugStore, DecisionError
    store = BugStore(_db(settings))
    try:
        row = store.resolve(args.repo, args.id)
        m = re.fullmatch(r"https://github\.com/([^/]+/[^/]+)/pull/(\d+)", args.url)
        if m is None or m.group(1).lower() != row["repository"]:
            raise DecisionError(f"{args.url} is not a pull request of {row['repository']}")
        data = {"number": int(m.group(2)), "origin": "human", "channel": "cli", "recorded_after_the_fact": True,
                **{k: v for k, v in (("merged_at", args.merged_at), ("merge_commit", args.merge_commit),
                                     ("link_evidence", args.evidence)) if v}}
        added = store.record_pr_event(row["fingerprint"], args.event, args.url, args.reason, data)
    except DecisionError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2
    print(f"{row['id']}: {args.event} {args.url} " + ("recorded" if added else "already recorded (no change)"))
    return 0


def cmd_contracts(settings, args) -> int:
    """Local Solidity analysis (syntax-level, synthetic/authorized code only). No chain, no network, no storage."""
    from pathlib import Path

    from .contracts import run
    from .engines.contract import DependencyMissing
    if not Path(args.path).exists():
        print(f"ERROR: {args.path}: no such file or directory", file=sys.stderr)
        return 2
    try:
        r = run(args.path, include_suppressed=args.include_suppressed)
    except DependencyMissing as e:
        print(f"MISSING DEPENDENCY: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(r, indent=2, default=str))
        return 0
    print(f"{r['engine']} {r['target']}: {len(r['files_scanned'])} file(s), {r['summary']}")
    for f in r["findings"]:
        loc = f["location"]
        print(f"  {f['status']:<14} {f['rule']:<24} {loc.get('file')}:{loc.get('line')} "
              f"{loc.get('contract')}.{loc.get('function')}")
    print("Candidates are not confirmed vulnerabilities. Nothing is stored or published.")
    return 0


def cmd_web(settings, args) -> int:
    """Passive analysis of LOCAL captures / HTML / JS files. Never sends a request."""
    from .web.capture import CaptureError
    from .web.engine import render_text, run
    try:
        r = run(args.path)
    except CaptureError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(json.dumps(r, indent=2, default=str) if args.json else render_text(r))
    loaded = r["inputs"].get("exchanges") or r["inputs"].get("resources")
    return 2 if r["inputs"].get("errors") and not loaded else 0


def _disc(settings):
    from .discovery.store import DiscoveryStore
    return DiscoveryStore(_db(settings))


def _disc_row(r) -> dict:
    j = json.loads(r["justification"] or "{}")
    f = json.loads(r["facts"] or "{}")
    v = lambda k: (f.get(k) or {}).get("value")  # noqa: E731
    return {"repository": r["display_name"], "url": v("html_url") or f"https://github.com/{r['display_name']}",
            "organisation": r["org_login"], "category": r["category"] if "category" in r.keys() else None,
            "description": v("description"), "language": v("language"), "stars": v("stars"),
            "last_push": v("pushed_at"), "commits_90d": v("commits_90d"),
            "external_merged_prs_90d": v("external_merged_prs_90d"),
            "external_closed_unmerged_90d": v("external_closed_unmerged_90d"),
            "contributing": v("contributing"), "ai_policy": v("ai_policy"), "ai_policy_excerpt": v("ai_policy_excerpt"),
            "requires_cla": v("requires_cla"), "test_files": v("test_files"), "ci": v("ci"),
            "score": r["score"], "score_version": r["score_version"], "tier": r["tier"],
            "recommendation": r["recommendation"], "components": j.get("components"), "reasons": j.get("reasons"),
            "excluded_because": j.get("excluded_because"), "penalties": j.get("penalties"), "notes": j.get("notes"),
            "missing": j.get("missing"), "human_decision": r["human_decision"], "human_reason": r["human_reason"],
            "first_seen": r["first_seen"], "last_checked": r["last_checked"], "enriched_at": r["enriched_at"]}


def cmd_discover(settings, args) -> int:
    """Read-only repository discovery. Never clones, scans, comments, opens issues/PRs or adds scan targets."""
    from .discovery import run as drun
    from .discovery.api import ReadOnlyGitHub
    from .discovery.catalog import load_catalog
    store = _disc(settings)
    out = None
    if args.action == "orgs":
        drun.sync_catalog(store, load_catalog(settings.root))
        added = drun.discover_orgs(store, ReadOnlyGitHub(), args.search, args.category or "community") \
            if args.search else []
        rows = store.orgs(args.category)
        out = {"added_pending": added, "organisations": [dict(r) | {"explorable": store.explorable(r)} for r in rows]}
        if not args.json:
            for r in rows:
                print(f"{r['display_login']:<18} {r['category']:<15} {r['origin']:<11} review={r['review_state']:<8} "
                      f"status={r['status']:<9} verified_domain={r['domain_verified']} "
                      f"{'explorable' if store.explorable(r) else 'NOT explored'}  {r['name'] or ''}")
            if added:
                print(f"added (pending your review): {', '.join(added)}")
            return 0
    elif args.action == "org-review":
        store.set_org_review(args.login, args.state, args.reason)
        out = dict(store.org(args.login))
    elif args.action == "refresh":
        out = drun.refresh(store, ReadOnlyGitHub(reserve=args.reserve), load_catalog(settings.root), args.org or None,
                           args.category, args.max_repos, args.enrich_top, args.stale_days,
                           max_repo_kb=settings.policies.max_repo_size_mb * 1024)
    elif args.action == "shortlist":
        rows = store.shortlist(args.org, args.category, args.all, args.limit)
        out = [{"rank": i + 1, **_disc_row(r)} for i, r in enumerate(rows)]
        if not args.json:
            for d in out:
                print(f"{d['rank']:>3}. [{d['recommendation']:<7}] {d['score']:>5}  {d['repository']:<45} "
                      f"{d['language'] or '?':<11} {d['category']:<14} ext-merged/90d={d['external_merged_prs_90d']} "
                      f"ai={d['ai_policy'] or '?'}  {'(' + d['human_decision'] + ')' if d['human_decision'] != 'none' else ''}")
            print("Shortlist of repositories worth a deeper look. No bug has been searched or found.")
            return 0
    elif args.action == "show":
        r = store.repo(args.repo)
        if r is None:
            raise cfg.ConfigError(f"unknown discovered repository {args.repo}")
        cat = store.org(r["org_login"])["category"]
        out = {**_disc_row(r), "category": cat, "facts": json.loads(r["facts"]),
               "events": [dict(e) for e in store.conn.execute(
                   "SELECT created_at, kind, field, old_value, new_value FROM disc_events WHERE subject=? ORDER BY id",
                   (r["full_name"],))],
               "errors": [dict(e) for e in store.conn.execute(
                   "SELECT created_at, endpoint, kind, message FROM disc_errors WHERE subject=? ORDER BY id",
                   (r["full_name"],))]}
    elif args.action in ("approve", "reject"):
        if args.action == "reject" and not args.reason:
            raise cfg.ConfigError("reject needs --reason")
        store.decide(args.repo, "approved" if args.action == "approve" else "rejected", args.reason)
        r = store.repo(args.repo)
        out = {"repository": r["display_name"], "human_decision": r["human_decision"], "reason": r["human_reason"],
               "note": "decision recorded only: no scan started, config/targets.yaml unchanged"}
    elif args.action == "rescore":
        out = {"rescored": store.rescore(max_repo_kb=settings.policies.max_repo_size_mb * 1024)}
    elif args.action == "stats":
        out = store.stats()
    print(json.dumps(out, indent=2, default=str))
    return 0


def cmd_hunt(settings, args) -> int:
    """Agentic logic-bug hunt (claude -p with sandboxed tools). Leaves local branches only; never pushes."""
    from .hunt import run as hunt_run
    from .hunt.lang import Toolchain
    opts = hunt_run.HuntOptions(files=args.files, budget_min=args.budget_min, lang=args.lang,
                                toolchain=Toolchain(python=args.python, go=args.go, node=args.node),
                                model=settings.policies.llm_model)
    out_dir = Path(__file__).resolve().parents[2] / "data" / "hunts"
    results, report = hunt_run.hunt(args.repo, Path(args.path).resolve(), opts, out_dir=out_dir)
    for r in results:
        where = f"{r.finding.file}:{r.finding.function}" if r.finding else r.target
        print(f"{r.status:<18} {where} {r.branch or ''} {r.detail.splitlines()[0] if r.detail else ''}")
    print(f"report: {report}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="github-sec", description="Policy-gated GitHub security research")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="tooling, auth and policy status").set_defaults(fn=cmd_status)
    sub.add_parser("config", help="show effective configuration").set_defaults(fn=cmd_config)
    c = sub.add_parser("check-target", help="read-only metadata of a candidate repo")
    c.add_argument("repo", metavar="OWNER/REPO")
    c.set_defaults(fn=cmd_check_target)
    c = sub.add_parser("clone", help="clone/update an in-scope repo")
    c.add_argument("repo", metavar="OWNER/REPO")
    c.set_defaults(fn=cmd_clone)
    c = sub.add_parser("scan", help="clone (if needed) + run scanners; report only")
    c.add_argument("repo", nargs="?", metavar="OWNER/REPO")
    c.add_argument("--path", help="scan a local directory instead (fixtures, own code)")
    c.add_argument("--with-bugs", action="store_true", help="also detect ordinary bug candidates (separate store)")
    c.set_defaults(fn=cmd_scan)
    c = sub.add_parser("bugs", help="ordinary bug candidates (Go, static; separate from security; no PR)")
    c.add_argument("repo", nargs="?", metavar="OWNER/REPO")
    c.add_argument("--path", help="local checkout (a workspace checkout keeps its target identity)")
    c.add_argument("--json", action="store_true")
    c.add_argument("--review", type=int, default=0, metavar="N",
                   help="LLM-review up to N unreviewed BUG_CANDIDATE (claude -p, no tools)")
    c.set_defaults(fn=cmd_bugs)
    c = sub.add_parser("bug", help="show one bug candidate: lifecycle, reproduction task, PR gate")
    c.add_argument("id")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_bug)
    d = sub.add_parser("discover", help="read-only discovery and ranking of public repositories of organisations")
    dsub = d.add_subparsers(dest="action", required=True)
    c = dsub.add_parser("orgs", help="list the organisation catalog; --search adds pending orgs from GitHub search")
    c.add_argument("--search", metavar="TERM")
    c.add_argument("--category", choices=("science_agency", "public_admin", "company", "foundation", "community"))
    c.add_argument("--json", action="store_true")
    c = dsub.add_parser("org-review", help="record your review of an organisation (approve to allow exploration)")
    c.add_argument("login")
    c.add_argument("state", choices=("approved", "rejected", "pending"))
    c.add_argument("--reason")
    c = dsub.add_parser("refresh", help="collect public metadata of explorable organisations and rank their repos")
    c.add_argument("--org", action="append", help="limit to this organisation (repeatable)")
    c.add_argument("--category", choices=("science_agency", "public_admin", "company", "foundation", "community"))
    c.add_argument("--max-repos", type=int, default=200, help="most recently pushed public repos listed per org")
    c.add_argument("--enrich-top", type=int, default=6, help="second-pass collection for the top N repos per org")
    c.add_argument("--reserve", type=int, default=500, help="stop when fewer API calls than this remain")
    c.add_argument("--stale-days", type=int, default=7, help="re-run the second pass when older than this (0 = always)")
    c = dsub.add_parser("shortlist", help="ranked repositories for human validation")
    c.add_argument("--org")
    c.add_argument("--category", choices=("science_agency", "public_admin", "company", "foundation", "community"))
    c.add_argument("--limit", type=int, default=25)
    c.add_argument("--all", action="store_true", help="include EXCLUDE and rejected repositories")
    c.add_argument("--json", action="store_true")
    c = dsub.add_parser("show", help="all collected facts, score justification and history of one repository")
    c.add_argument("repo", metavar="OWNER/REPO")
    for name, hlp in (("approve", "mark a repository approved for a FUTURE scan (no scan started)"),
                      ("reject", "mark a repository rejected (reason required)")):
        c = dsub.add_parser(name, help=hlp)
        c.add_argument("repo", metavar="OWNER/REPO")
        c.add_argument("--reason")
    dsub.add_parser("rescore", help="recompute every stored score with the current criteria")
    dsub.add_parser("stats", help="discovery statistics")
    d.set_defaults(fn=cmd_discover, json=False)
    c = sub.add_parser("bug-reject", help="record a reasoned human rejection of one bug candidate")
    c.add_argument("repo", help="OWNER/REPO (or local:NAME) the candidate must belong to")
    c.add_argument("id", help="candidate short id or fingerprint")
    c.add_argument("--reason", required=True, help="specific justification for THIS candidate")
    c.set_defaults(fn=cmd_bug_reject)
    c = sub.add_parser("bug-pr", help="record the real outcome of a PR fixing a bug candidate (nothing is sent)")
    c.add_argument("repo")
    c.add_argument("id")
    c.add_argument("--event", required=True, choices=["PR_CREATED", "PR_UPDATED", "CHANGES_REQUESTED", "PR_CLOSED",
                                                      "PR_MERGED"])
    c.add_argument("--url", required=True)
    c.add_argument("--merged-at")
    c.add_argument("--merge-commit")
    c.add_argument("--evidence", help="why this PR fixes this candidate (checked facts)")
    c.add_argument("--reason")
    c.set_defaults(fn=cmd_bug_pr)
    k = sub.add_parser("contracts", help="local Solidity security analysis (no chain, no network)")
    ksub = k.add_subparsers(dest="ccmd", required=True)
    c = ksub.add_parser("scan", help="analyse local .sol files under PATH (report only, nothing stored)")
    c.add_argument("path")
    c.add_argument("--json", action="store_true")
    c.add_argument("--include-suppressed", action="store_true", help="also list guarded sites as FALSE_POSITIVE")
    c.set_defaults(fn=cmd_contracts)
    w = sub.add_parser("web", help="passive web analysis of local captures (never sends a request)")
    wsub = w.add_subparsers(dest="wcmd", required=True)
    c = wsub.add_parser("analyze", help="analyse a capture file or directory (.http/.resp, web-capture/1 JSON, .html, .js)")
    c.add_argument("path")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_web)
    c = sub.add_parser("bug-metrics", help="bug funnel: candidate -> validated -> test -> patch -> PR -> merge")
    c.add_argument("--repo")
    c.set_defaults(fn=cmd_bug_metrics)
    c = sub.add_parser("findings", help="list stored findings")
    c.add_argument("--repo")
    c.add_argument("--all", action="store_true", help="include findings no longer present")
    c.set_defaults(fn=cmd_findings)
    c = sub.add_parser("finding", help="show one finding: detection, LLM, evidence, confidence, decision")
    c.add_argument("id")
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_finding)
    c = sub.add_parser("review", help="LLM contextual review (claude -p, no tools)")
    c.add_argument("id", nargs="?")
    c.add_argument("--repo")
    c.add_argument("--limit", type=int, default=10)
    c.set_defaults(fn=cmd_review)
    c = sub.add_parser("hunt", help="agentic logic-bug hunt on a local checkout (local branches only, no PR)")
    c.add_argument("repo", help="owner/name")
    c.add_argument("--path", required=True, help="local git checkout of the repo")
    c.add_argument("--files", type=int, default=8)
    c.add_argument("--budget-min", type=int, default=20)
    c.add_argument("--lang", choices=["auto", "py", "go", "js"], default="auto")
    c.add_argument("--python", default="python3")
    c.add_argument("--go", default="go")
    c.add_argument("--node", default="node")
    c.set_defaults(fn=cmd_hunt)
    c = sub.add_parser("validate", help="static validation + verdict (never executes target code)")
    c.add_argument("id", nargs="?")
    c.add_argument("--repo")
    c.add_argument("--limit", type=int, default=50)
    c.set_defaults(fn=cmd_validate)
    c = sub.add_parser("analyze", help="full pipeline with pre-LLM static triage (recommended)")
    c.add_argument("id", nargs="?")
    c.add_argument("--repo")
    c.add_argument("--limit", type=int, default=100)
    c.set_defaults(fn=cmd_analyze)
    c = sub.add_parser("draft-test", help="LLM regression-test DRAFT (UNEXECUTED, not evidence)")
    c.add_argument("id")
    c.set_defaults(fn=cmd_draft_test)
    c = sub.add_parser("review-queue", help="findings awaiting human review")
    c.add_argument("--repo")
    c.set_defaults(fn=cmd_review_queue)
    c = sub.add_parser("metrics", help="detection / validation metrics")
    c.add_argument("--repo")
    c.set_defaults(fn=cmd_metrics)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = cfg.load()
        obs.configure(settings.log_dir)
        return args.fn(settings, args)
    except PolicyViolation as e:
        obs.event("policy", "violation", error=str(e))
        print(f"POLICY: {e}", file=sys.stderr)
        return 3
    except (cfg.ConfigError, client.GitHubError, repositories.CloneError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
