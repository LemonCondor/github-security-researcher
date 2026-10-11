"""One discovery campaign: catalog sync -> org profiles -> repo listing -> first score -> bounded enrichment
-> final score. Read-only GitHub calls only. A quota shortage stops the run cleanly (status stopped_rate_limit)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ..observability import event
from . import collect
from .api import DiscoveryError, RateLimited, ReadOnlyGitHub
from .catalog import OrgSpec
from .store import DiscoveryStore


def sync_catalog(store: DiscoveryStore, specs: list[OrgSpec]) -> int:
    new = 0
    with store.db.tx():
        for s in specs:
            new += store.upsert_org(s.login, s.category, "configured", "config/organizations.yaml",
                                    **({"name": s.label} if s.label else {}))
    return new


def refresh(store: DiscoveryStore, api: ReadOnlyGitHub, specs: list[OrgSpec], orgs: list[str] | None = None,
            category: str | None = None, max_repos: int = 200, enrich_top: int = 6, stale_days: int = 7,
            now: datetime | None = None, max_repo_kb: int | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    sync_catalog(store, specs)
    wanted = {o.lower() for o in orgs} if orgs else None
    rows = [r for r in store.orgs(category) if (wanted is None or r["login"] in wanted)]
    unknown = sorted(wanted - {r["login"] for r in rows}) if wanted else []
    rows = [r for r in rows if store.explorable(r)]
    rid = store.start_run([r["login"] for r in rows])
    stats = {"orgs_requested": len(rows), "orgs_examined": 0, "orgs_not_found": 0, "repos_listed": 0,
             "repos_new": 0, "repos_renamed": 0, "repos_enriched": 0, "errors": 0, "api_calls": 0,
             "skipped_not_in_catalog_or_not_explorable": unknown}
    status = "done"
    api.check_quota()
    try:
        for org in rows:
            login = org["login"]
            try:
                prof = collect.org_profile(api, login)
            except RateLimited:
                raise
            except DiscoveryError as e:
                stats["errors"] += 1
                store.error(rid, "org", login, f"orgs/{login}", e.kind, str(e))
                if e.kind == "not_found":
                    stats["orgs_not_found"] += 1
                    store.upsert_org(login, org["category"], org["origin"], status="not_found",
                                     verified_at=now.isoformat())
                continue
            try:
                listing = collect.list_repos(api, login, max_repos)
            except RateLimited:
                raise
            except DiscoveryError as e:
                stats["errors"] += 1
                store.error(rid, "org", login, f"orgs/{login}/repos", e.kind, str(e))
                continue
            stats["orgs_examined"] += 1
            last_push = max((r.get("pushed_at") or "" for r in listing), default="")
            active = bool(last_push) and (now - datetime.fromisoformat(last_push.replace("Z", "+00:00"))
                                          < timedelta(days=365))
            with store.db.tx():
                store.upsert_org(login, org["category"], org["origin"], status="active" if active else "inactive",
                                 verified_at=now.isoformat(), **prof)
                for raw in listing:
                    st = store.upsert_repo(login, raw, collect.listing_facts(raw, login))
                    stats["repos_listed"] += 1
                    stats[f"repos_{st}"] = stats.get(f"repos_{st}", 0) + 1
            with store.db.tx():
                for r in store.repos(login):
                    store.rescore(r["full_name"], max_repo_kb)
            # second pass: best non-excluded repos of this org whose enrichment is missing or stale
            cands = sorted((r for r in store.repos(login) if r["recommendation"] != "EXCLUDE"),
                           key=lambda r: -(r["score"] or 0))
            done = 0
            for r in cands:
                if done >= enrich_top:
                    break
                if r["enriched_at"] and now - datetime.fromisoformat(r["enriched_at"]) < timedelta(days=stale_days):
                    done += 1
                    continue
                facts, errors = collect.enrich(api, r["display_name"], json.loads(r["facts"]), now)
                for e in errors:
                    stats["errors"] += 1
                    store.error(rid, "repo", r["full_name"], e["endpoint"], e["kind"], e["message"])
                store.add_enrichment(r["full_name"], facts)
                store.rescore(r["full_name"], max_repo_kb)
                stats["repos_enriched"] += 1
                done += 1
            event("discovery", "org.done", org=login, repos=len(listing), calls=api.calls)
    except RateLimited as e:
        status = "stopped_rate_limit"
        stats["errors"] += 1
        store.error(rid, "run", "github", None, "rate_limited", str(e))
    stats["api_calls"] = api.calls
    stats["quota_remaining_estimate"] = api.remaining
    store.finish_run(rid, status, stats)
    return {"run_id": rid, "status": status, **stats}


def discover_orgs(store: DiscoveryStore, api: ReadOnlyGitHub, term: str, category: str, limit: int = 20) -> list[str]:
    """Add organisations found by a GitHub search as origin=discovered, review_state=pending (never explored
    before the user approves them)."""
    added = []
    for o in collect.search_orgs(api, term, limit):
        if store.upsert_org(o["login"], category, "discovered", f"search:{term}", github_url=o["github_url"]):
            added.append(o["login"])
    return added
