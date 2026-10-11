"""Deterministic repository priority score (0-100) with a readable justification.

It ranks repositories worth a deeper look by the existing pipeline; it never claims a bug exists.
Stars are displayed but deliberately NOT scored. Unknown facts contribute 0 and are listed as `missing`.
SCORE_VERSION changes whenever criteria change; `discover rescore` recomputes stored repositories.
"""
from __future__ import annotations

from datetime import datetime, timezone

SCORE_VERSION = "disc-score/3"   # 2: REVIEW needs >=1 external merged PR; 3: <15% source files (assets
                                 #    excluded) penalised and kept out of REVIEW
WEIGHTS = {"organisation": 0.10, "activity": 0.25, "receptivity": 0.30, "feasibility": 0.35}
ORG_IMPORTANCE = {"science_agency": 1.0, "public_admin": 1.0, "foundation": 0.9, "company": 0.8, "community": 0.6}
# What the existing detectors can do per language (see PROJECT_STATE): Go = bug detectors + GoDataflow +
# semgrep p/golang + OSV; Python = internal semgrep taint rules + OSV; JS/TS = OSV(npm) + gitleaks only.
LANGUAGE_SUPPORT = {"Go": (1.0, "bug detectors, GoDataflow, semgrep p/golang, OSV, gitleaks"),
                    "Python": (0.6, "semgrep internal rules, OSV, gitleaks"),
                    "JavaScript": (0.35, "OSV (npm), gitleaks"), "TypeScript": (0.35, "OSV (npm), gitleaks")}
OTHER_LANGUAGE = (0.15, "gitleaks, OSV only")
REVIEW_MIN_SCORE = 55
DIFFICULT_KB = 500 * 1024               # policies.max_repo_size_mb default


def _v(facts: dict, key: str):
    f = facts.get(key)
    return f.get("value") if isinstance(f, dict) else None


def _days(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    return (now - datetime.fromisoformat(iso.replace("Z", "+00:00"))).days


def _step(x, steps: list[tuple[float, float]], default: float = 0.0) -> float:
    for threshold, val in steps:
        if x >= threshold:
            return val
    return default


def score(facts: dict, category: str, now: datetime | None = None, max_repo_kb: int = DIFFICULT_KB) -> dict:
    now = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    missing: list[str] = []
    excluded: list[str] = []
    penalties: list[tuple[int, str]] = []
    notes: list[str] = []

    # E. hard constraints
    for key, why in (("archived", "archived"), ("disabled", "disabled"), ("fork", "fork (no own development)"),
                     ("is_template", "template repository")):
        if _v(facts, key):
            excluded.append(why)
    if _v(facts, "mirror_url"):
        excluded.append("mirror of another repository")
    desc = (_v(facts, "description") or "")
    topics = _v(facts, "topics") or []
    if any(w in desc.lower() for w in ("deprecated", "no longer maintained", "unmaintained")) or \
            "deprecated" in topics:
        excluded.append("declared deprecated/unmaintained")
    push_days = _days(_v(facts, "pushed_at"), now)
    if push_days is not None and push_days > 365:
        excluded.append(f"inactive: last push {push_days} days ago")
    ai = _v(facts, "ai_policy")
    if ai == "prohibited":
        excluded.append("contribution policy refuses AI-assisted contributions")

    # A. organisation (low weight: importance alone must not promote a repository)
    a = ORG_IMPORTANCE.get(category, 0.6)

    # B. activity
    if push_days is None:
        missing.append("last push date")
        push = 0.0
    else:
        push = _step(-push_days, [(-30, 1.0), (-90, 0.75), (-180, 0.45), (-365, 0.2)])
        reasons.append(f"last push {push_days} d ago")
    commits = _v(facts, "commits_90d")
    if commits is None:
        missing.append("commits in last 90 days")
        b = push * 0.5
    else:
        c = _step(commits, [(50, 1.0), (15, 0.8), (5, 0.6), (1, 0.3)])
        b = 0.5 * push + 0.5 * c
        reasons.append(f"{commits}{'+' if commits >= 100 else ''} commits in 90 d")

    # C. receptivity to external contributions
    ext = _v(facts, "external_merged_prs_90d")
    ext_closed = _v(facts, "external_closed_unmerged_90d")
    contributing = _v(facts, "contributing")
    if ext is None:
        missing.append("external PRs merged in 90 days")
        e = acc = 0.0
    else:
        e = _step(ext, [(5, 1.0), (2, 0.7), (1, 0.45)], 0.1 if (_v(facts, "merged_prs_90d") or 0) else 0.0)
        tot = ext + (ext_closed or 0)
        acc = (ext / tot) if tot else 0.0
        reasons.append(f"{ext} external PR(s) merged / {ext_closed or 0} closed unmerged in 90 d")
        if ext == 0 and (ext_closed or 0) >= 5:
            penalties.append((15, f"{ext_closed} external PRs closed without merge, none merged (90 d)"))
    if contributing is None:
        missing.append("contribution guide")
    elif contributing:
        reasons.append("CONTRIBUTING guide present")
    c_score = 0.6 * e + 0.25 * acc + 0.15 * (1.0 if contributing else 0.0)
    if ai == "conditions":
        notes.append("AI policy with conditions (e.g. disclosure): read before contributing")
    elif ai in (None, "unknown"):
        missing.append("AI contribution policy")

    # D. technical feasibility with our tools
    lang = _v(facts, "language")
    lang_score, tools = LANGUAGE_SUPPORT.get(lang, OTHER_LANGUAGE) if lang else (0.0, "unknown language")
    if not lang:
        missing.append("primary language")
    size_kb = _v(facts, "size_kb")
    difficult = False
    if size_kb is None:
        missing.append("repository size")
        size = 0.0
    elif size_kb > max_repo_kb:
        size, difficult = 0.0, True
        notes.append(f"repository size {size_kb // 1024} MB above the clone limit")
    else:
        size = 1.0 if 200 <= size_kb <= 100_000 else (0.5 if size_kb > 100_000 else 0.4)
    tests = _v(facts, "test_files")
    if tests is None:
        missing.append("tests")
        t = 0.0
    else:
        t = _step(tests, [(10, 1.0), (1, 0.6)])
        reasons.append(f"{tests} test file(s) (path heuristic)")
    ci = _v(facts, "ci")
    if ci is None:
        missing.append("CI")
    elif ci:
        reasons.append("CI: " + ", ".join(ci[:3]))
    d = 0.45 * lang_score + 0.20 * size + 0.25 * t + 0.10 * (1.0 if ci else 0.0)
    if lang:
        reasons.append(f"{lang}: {tools}")

    lic = _v(facts, "license")
    if "license" not in facts:
        missing.append("license")
    elif lic is None:
        penalties.append((15, "no license"))
    elif lic == "NOASSERTION":
        penalties.append((5, "license not recognised by GitHub (NOASSERTION)"))
    code_share = _v(facts, "code_share")
    if code_share is not None and code_share < 0.15:
        penalties.append((20, f"only {round(code_share * 100)}% of files are source code (mostly docs/data/config)"))
    vend = _v(facts, "vendored_share")
    if vend is not None and vend > 0.5:
        penalties.append((10, f"{int(vend * 100)}% of files are vendored dependencies"))
    if re_generated(desc):
        penalties.append((10, "description says generated code"))
    code_bytes = _v(facts, "code_bytes")
    if code_bytes is not None and code_bytes > 60_000_000:
        difficult = True
        notes.append(f"{code_bytes // 1_000_000} MB of source code")

    comps = {"organisation": a, "activity": round(b, 3), "receptivity": round(c_score, 3),
             "feasibility": round(d, 3)}
    raw = 100 * sum(WEIGHTS[k] * v for k, v in comps.items())
    total = max(0.0, round(raw - sum(p for p, _ in penalties), 1))
    enriched = "test_files" in facts or "external_merged_prs_90d" in facts
    if excluded:
        tier, rec = "excluded", "EXCLUDE"
    elif difficult:
        tier, rec = "difficult", "DEFER"
    elif enriched and total >= REVIEW_MIN_SCORE and lang_score >= 0.6 and (ext or 0) >= 1 and \
            (code_share is None or code_share >= 0.15):
        tier, rec = "candidate", "REVIEW"
    else:
        tier, rec = "candidate", "DEFER"
    if rec == "DEFER" and not enriched and not difficult:
        notes.append("metadata only (second pass not run): not eligible for REVIEW yet")
    elif rec == "DEFER" and enriched and ext == 0:
        notes.append("no external PR merged in 90 days: receptivity to outside contributions not shown")
    if rec == "DEFER" and code_share is not None and code_share < 0.15:
        notes.append("little source code: code bug fixes unlikely, kept out of REVIEW")
    return {"score": total, "tier": tier, "recommendation": rec, "version": SCORE_VERSION,
            "components": comps, "weights": WEIGHTS, "reasons": reasons, "excluded_because": excluded,
            "penalties": [{"points": p, "reason": r} for p, r in penalties], "notes": notes,
            "missing": sorted(set(missing))}


def re_generated(desc: str) -> bool:
    from .collect import GENERATED_DESC
    return bool(GENERATED_DESC.search(desc or ""))
