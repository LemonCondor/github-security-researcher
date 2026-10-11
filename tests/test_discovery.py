"""Repository discovery (read-only): metadata collection, pagination, API errors, quota, scoring, dedup,
history, human decisions, migration, JSON CLI. Synthetic data / fake GitHub only: no network."""
import ast
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from github_security.discovery import collect
from github_security.discovery.api import DiscoveryError, NotFound, RateLimited, ReadOnlyGitHub, classify
from github_security.discovery.catalog import OrgSpec, load_catalog
from github_security.discovery.run import discover_orgs, refresh
from github_security.discovery.scoring import score
from github_security.discovery.store import DiscoveryStore
from github_security.github.client import GitHubError
from github_security.storage.database import SCHEMA_VERSION, Database

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def raw_repo(rid, name, org="acme", **kw):
    base = {"id": rid, "full_name": f"{org}/{name}", "description": f"{name} tool", "language": "Go",
            "stargazers_count": 10, "forks_count": 2, "pushed_at": iso(5), "created_at": iso(900),
            "default_branch": "main", "open_issues_count": 3, "archived": False, "disabled": False, "fork": False,
            "is_template": False, "mirror_url": None, "visibility": "public", "size": 4000,
            "html_url": f"https://github.com/{org}/{name}", "topics": [], "has_issues": True,
            "license": {"spdx_id": "Apache-2.0"}}
    base.update(kw)
    return base


class FakeGitHub:
    """Maps API paths to responses; pagination emulated from ?per_page=&page=. Records every call."""

    def __init__(self, orgs=None, repos=None, extra=None, fail=None, remaining=5000):
        self.orgs, self.repos, self.extra, self.fail = orgs or {}, repos or {}, extra or {}, fail or {}
        self.calls: list[str] = []
        self.remaining = remaining

    def __call__(self, path: str):
        self.calls.append(path)
        if path == "rate_limit":
            return {"resources": {"core": {"remaining": self.remaining}}}
        for pat, err in self.fail.items():
            if re.search(pat, path):
                raise GitHubError(err)
        m = re.match(r"orgs/([^/?]+)$", path)
        if m:
            if m.group(1) not in self.orgs:
                raise GitHubError("gh: Not Found (HTTP 404)")
            return self.orgs[m.group(1)]
        m = re.match(r"orgs/([^/]+)/repos\?.*per_page=(\d+)&page=(\d+)", path)
        if m:
            items, per, page = self.repos.get(m.group(1), []), int(m.group(2)), int(m.group(3))
            return items[(page - 1) * per: page * per]
        for pat, resp in self.extra.items():
            if re.search(pat, path):
                return resp
        raise GitHubError(f"gh: Not Found (HTTP 404) {path}")


def enrich_responses(full="acme/core", ext_merged=4, tests=12, policy="Please open an issue first.", lang=None):
    pulls = [{"user": {"type": "User"}, "author_association": "CONTRIBUTOR", "closed_at": iso(10),
              "merged_at": iso(10)} for _ in range(ext_merged)]
    pulls += [{"user": {"type": "Bot"}, "author_association": "NONE", "closed_at": iso(3), "merged_at": iso(3)}]
    tree = [{"path": f"pkg/x{i}_test.go", "type": "blob"} for i in range(tests)] + \
        [{"path": "main.go", "type": "blob"}, {"path": ".github/workflows/ci.yml", "type": "blob"},
         {"path": "CONTRIBUTING.md", "type": "blob"}]
    import base64
    return {rf"repos/{full}/git/trees/": {"tree": tree, "truncated": False},
            rf"repos/{full}/languages": lang or {"Go": 90000, "Shell": 1000},
            rf"repos/{full}/community/profile": {"health_percentage": 80, "files": {"contributing": {"url": "x"}}},
            rf"repos/{full}/commits\?since=": [{}] * 40,
            rf"repos/{full}/pulls\?state=closed": pulls,
            rf"repos/{full}/contents/CONTRIBUTING.md": {"encoding": "base64",
                                                        "content": base64.b64encode(policy.encode()).decode()}}


def make(tmp_path, gh, specs=(OrgSpec("acme", "science_agency", "ACME"),), **kw):
    db = Database(tmp_path / "g.db")
    store = DiscoveryStore(db)
    res = refresh(store, ReadOnlyGitHub(gh, reserve=kw.pop("reserve", 10)), list(specs), now=NOW, **kw)
    return store, res


def facts_of(store, full):
    return json.loads(store.repo(full)["facts"])


# --------------------------------------------------------------------------- collection / pagination

def test_listing_facts_keep_provenance_and_unknowns():
    f = collect.listing_facts(raw_repo(1, "core"), "acme")
    assert f["language"] == {"value": "Go", "source": "api:orgs/acme/repos"}
    assert f["license"]["value"] == "Apache-2.0" and f["stars"]["value"] == 10
    partial = collect.listing_facts({"id": 2, "full_name": "acme/x"}, "acme")
    assert partial == {}                                  # absent = unknown, never invented


def test_pagination_follows_pages_and_caps():
    gh = FakeGitHub(repos={"acme": [raw_repo(i, f"r{i}") for i in range(230)]})
    api = ReadOnlyGitHub(gh)
    assert len(api.paginate("orgs/acme/repos?type=public", 1000)) == 230
    assert [c for c in gh.calls if "page=" in c][-1].endswith("page=3")
    gh.calls.clear()
    assert len(api.paginate("orgs/acme/repos?type=public", 150)) == 150 and len(gh.calls) == 2


def test_refresh_collects_and_enriches_top_repos(tmp_path):
    repos = [raw_repo(1, "core"), raw_repo(2, "docs", language="HTML", size=50)]
    gh = FakeGitHub(orgs={"acme": {"login": "acme", "name": "ACME", "is_verified": True, "blog": "https://acme.org",
                                   "public_repos": 2}},
                    repos={"acme": repos}, extra=enrich_responses())
    store, res = make(tmp_path, gh, enrich_top=1)
    assert (res["status"], res["orgs_examined"], res["repos_listed"], res["repos_new"], res["repos_enriched"]) == \
        ("done", 1, 2, 2, 1)
    org = store.org("acme")
    assert (org["domain_verified"], org["website"], org["status"], org["origin"]) == (1, "https://acme.org",
                                                                                   "active", "configured")
    f = facts_of(store, "acme/core")
    assert f["external_merged_prs_90d"]["value"] == 4 and f["merged_prs_90d"]["value"] == 4   # bot excluded
    assert f["test_files"]["value"] == 12 and f["ci"]["value"] == [".github/workflows"]
    assert f["ai_policy"]["value"] == "none_found" and f["commits_90d"]["value"] == 40
    assert f["docs_share"]["value"] == 0.067                       # 1 CONTRIBUTING.md out of 15 files
    assert f["code_share"]["value"] == 0.867                       # 13 .go files out of 15
    assert store.repo("acme/docs")["enriched_at"] is None          # only the top 1 got the second pass
    assert store.repo("acme/core")["recommendation"] == "REVIEW"


# --------------------------------------------------------------------------- errors / quota

def test_unknown_org_and_api_errors_are_recorded_not_fatal(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core")]},
                    extra=enrich_responses(), fail={r"repos/acme/core/pulls": "HTTP 502 bad gateway"})
    store, res = make(tmp_path, gh, specs=[OrgSpec("ghost", "company"), OrgSpec("acme", "company")])
    assert res["status"] == "done" and res["orgs_not_found"] == 1 and res["orgs_examined"] == 1
    assert store.org("ghost")["status"] == "not_found"
    kinds = {(r["subject"], r["kind"]) for r in store.conn.execute("SELECT * FROM disc_errors")}
    assert ("ghost", "not_found") in kinds and ("acme/core", "api_error") in kinds
    f = facts_of(store, "acme/core")
    assert "external_merged_prs_90d" not in f and f["test_files"]["value"] == 12   # only that field unknown
    assert "external PRs merged in 90 days" in json.loads(store.repo("acme/core")["justification"])["missing"]


def test_quota_reserve_stops_run_cleanly(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core")]},
                    extra=enrich_responses(), remaining=12)
    store, res = make(tmp_path, gh, reserve=10)
    assert res["status"] == "stopped_rate_limit"
    assert store.conn.execute("SELECT status FROM disc_runs").fetchone()[0] == "stopped_rate_limit"
    assert isinstance(classify(GitHubError("API rate limit exceeded for user")), RateLimited)
    assert isinstance(classify(GitHubError("HTTP 404: Not Found")), NotFound)
    with pytest.raises(DiscoveryError):
        ReadOnlyGitHub(gh).get("repos/a/../../user")


# --------------------------------------------------------------------------- scoring

def F(**kw):
    return {k: {"value": v, "source": "test"} for k, v in kw.items()}


GOOD = dict(language="Go", pushed_at=iso(3), size_kb=5000, license="MIT", commits_90d=60,
            external_merged_prs_90d=6, external_closed_unmerged_90d=1, merged_prs_90d=20, contributing=True,
            test_files=40, ci=[".github/workflows"], ai_policy="none_found", stars=10)


def test_score_review_and_stars_ignored():
    s = score(F(**GOOD), "foundation", NOW)
    assert s["recommendation"] == "REVIEW" and s["tier"] == "candidate" and s["score"] >= 55
    assert score(F(**{**GOOD, "stars": 90000}), "foundation", NOW)["score"] == s["score"]
    assert any("external PR" in r for r in s["reasons"]) and s["missing"] == []


@pytest.mark.parametrize("change,why", [
    ({"archived": True}, "archived"), ({"fork": True}, "fork"), ({"pushed_at": iso(500)}, "inactive"),
    ({"mirror_url": "git://x"}, "mirror"), ({"ai_policy": "prohibited"}, "AI"),
    ({"description": "DEPRECATED: use v2"}, "deprecated"),
])
def test_hard_constraints_exclude(change, why):
    s = score(F(**{**GOOD, **change}), "company", NOW)
    assert s["recommendation"] == "EXCLUDE" and any(why.lower() in e.lower() for e in s["excluded_because"])


def test_soft_constraints_and_difficult_tier():
    base = score(F(**GOOD), "company", NOW)["score"]
    nolic = score(F(**{**GOOD, "license": None}), "company", NOW)
    assert nolic["score"] == base - 15 and nolic["penalties"][0]["reason"] == "no license"
    big = score(F(**{**GOOD, "size_kb": 900_000}), "company", NOW)
    assert (big["tier"], big["recommendation"]) == ("difficult", "DEFER")           # kept, not excluded
    js = score(F(**{**GOOD, "language": "JavaScript"}), "company", NOW)
    assert js["recommendation"] == "DEFER"                                         # weak tool support
    cond = score(F(**{**GOOD, "ai_policy": "conditions"}), "company", NOW)
    assert cond["recommendation"] == "REVIEW" and any("AI policy" in n for n in cond["notes"])


def test_review_requires_proven_external_receptivity():
    zero = score(F(**{**GOOD, "external_merged_prs_90d": 0, "external_closed_unmerged_90d": 0}), "company", NOW)
    assert zero["recommendation"] == "DEFER" and any("no external PR merged" in n for n in zero["notes"])
    unknown = {k: v for k, v in GOOD.items() if not k.startswith("external")}
    s = score(F(**unknown), "foundation", NOW)          # e.g. pulls endpoint unavailable (kubernetes/client-go)
    assert s["recommendation"] == "DEFER" and "external PRs merged in 90 days" in s["missing"]


def test_code_share_ignores_assets():
    # numerique-gouv/django-dsfr: 1150 svg icons must not hide 74 Python files
    paths = [f"icons/i{i}.svg" for i in range(1150)] + [f"dsfr/m{i}.py" for i in range(74)] + \
        [f"docs/p{i}.md" for i in range(100)]
    assert collect.code_share(paths) == round(74 / 174, 3)
    kep = [f"keps/k{i}/kep.yaml" for i in range(1207)] + [f"keps/k{i}/README.md" for i in range(721)] + \
        [f"cmd/c{i}.go" for i in range(35)]
    assert collect.code_share(kep) < 0.02
    assert collect.code_share(["logo.png"]) == 0.0


def test_mostly_non_code_is_penalised():
    base = score(F(**GOOD), "foundation", NOW)
    # e.g. kubernetes/enhancements: 1207 yaml + 721 md vs 35 go files
    kep = score(F(**{**GOOD, "code_share": 0.03}), "foundation", NOW)
    assert kep["score"] == round(base["score"] - 20, 1)
    assert kep["penalties"][0]["reason"].startswith("only 3% of files are source code")
    assert score(F(**{**GOOD, "code_share": 0.5}), "foundation", NOW)["score"] == base["score"]
    assert kep["recommendation"] == "DEFER" and any("source code" in n for n in kep["notes"])   # blocks REVIEW


def test_missing_metadata_never_reviewed():
    s = score(F(language="Go", pushed_at=iso(2)), "science_agency", NOW)
    assert s["recommendation"] == "DEFER" and {"tests", "license", "external PRs merged in 90 days"} <= set(s["missing"])
    assert score({}, "company", NOW)["recommendation"] == "DEFER"


def test_ai_policy_classifier():
    k8s = ("Using AI tools to help write your PR is acceptable, but you must disclose this. "
           "AI generated commit messages are not allowed.")
    assert collect.classify_ai_policy(k8s)[0] == "conditions"
    assert collect.classify_ai_policy("We do not accept AI-generated contributions.")[0] == "prohibited"
    assert collect.classify_ai_policy("Run make test before sending a PR.") == ("none_found", None)
    assert collect.classify_ai_policy("We use an LLM to triage issues.")[0] == "mentioned"


# --------------------------------------------------------------------------- dedup / history / update

def test_dedup_rename_and_change_history(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core")]},
                    extra=enrich_responses())
    store, _ = make(tmp_path, gh)
    enriched = facts_of(store, "acme/core")["test_files"]
    gh.repos["acme"] = [raw_repo(1, "core-ng", archived=True)]                     # renamed + archived
    gh.extra = enrich_responses("acme/core-ng")
    res = refresh(store, ReadOnlyGitHub(gh, reserve=10), [OrgSpec("acme", "science_agency")], now=NOW)
    assert res["repos_new"] == 0 and res["repos_renamed"] == 1
    assert store.conn.execute("SELECT COUNT(*) FROM disc_repos").fetchone()[0] == 1
    assert store.repo("acme/core") is None and store.repo("acme/core-ng")["recommendation"] == "EXCLUDE"
    kinds = [(e["kind"], e["field"]) for e in store.conn.execute("SELECT * FROM disc_events WHERE subject='acme/core-ng'")]
    assert ("RENAMED", "full_name") in kinds and ("CHANGED", "archived") in kinds
    assert facts_of(store, "acme/core-ng")["test_files"] == enriched              # second-pass facts kept
    again = refresh(store, ReadOnlyGitHub(gh, reserve=10), [OrgSpec("acme", "science_agency")], now=NOW)
    assert again["repos_new"] == 0 and again["repos_known"] == 1


def test_rescore_after_criteria_change(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core", size=600_000)]},
                    extra=enrich_responses())
    store, _ = make(tmp_path, gh)
    assert store.repo("acme/core")["tier"] == "difficult"
    store.rescore(max_repo_kb=2_000_000)                    # e.g. the clone size limit was raised
    assert store.repo("acme/core")["tier"] == "candidate"


# --------------------------------------------------------------------------- orgs / decisions / read-only

def test_discovered_orgs_pending_until_approved(tmp_path):
    db = Database(tmp_path / "g.db")
    store = DiscoveryStore(db)
    gh = FakeGitHub(extra={r"search/users\?q=space": {"items": [
        {"login": "spaceorg", "type": "Organization", "html_url": "u"}, {"login": "bob", "type": "User"}]}},
        orgs={"spaceorg": {"login": "spaceorg"}}, repos={"spaceorg": [raw_repo(9, "x", org="spaceorg")]})
    assert discover_orgs(store, ReadOnlyGitHub(gh), "space", "science_agency") == ["spaceorg"]
    row = store.org("spaceorg")
    assert (row["origin"], row["review_state"], store.explorable(row)) == ("discovered", "pending", False)
    res = refresh(store, ReadOnlyGitHub(gh), [], now=NOW)
    assert res["orgs_requested"] == 0 and store.repos() == []
    store.set_org_review("spaceorg", "approved", "checked the official site")
    assert refresh(store, ReadOnlyGitHub(gh), [], now=NOW)["repos_new"] == 1
    store.set_org_review("spaceorg", "rejected")
    assert not store.explorable(store.org("spaceorg"))


def test_human_decisions_and_shortlist(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}},
                    repos={"acme": [raw_repo(1, "core"), raw_repo(2, "old", archived=True)]},
                    extra=enrich_responses())
    store, _ = make(tmp_path, gh)
    assert [r["display_name"] for r in store.shortlist()] == ["acme/core"]          # EXCLUDE hidden
    assert {r["display_name"] for r in store.shortlist(include_excluded=True)} == {"acme/core", "acme/old"}
    store.decide("acme/core", "approved", "good fit")
    assert store.repo("acme/core")["human_decision"] == "approved"
    store.decide("acme/core", "rejected", "too much infra")
    assert store.shortlist() == []
    ev = [(e["kind"], e["new_value"]) for e in store.conn.execute("SELECT * FROM disc_events WHERE kind='DECISION'")]
    assert ev == [("DECISION", '"approved"'), ("DECISION", '"rejected"')]
    for t in ("findings", "bug_candidates", "scans"):                               # nothing else touched
        assert store.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0


def test_only_get_paths_and_no_write_code():
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core")]},
                    extra=enrich_responses())
    store = DiscoveryStore(Database(":memory:"))
    refresh(store, ReadOnlyGitHub(gh, reserve=10), [OrgSpec("acme", "company")], now=NOW)
    assert gh.calls and all(not c.startswith("-") for c in gh.calls)
    root = Path(__file__).parents[1] / "src" / "github_security" / "discovery"
    for f in root.glob("*.py"):
        src = f.read_text()
        tree = ast.parse(src)
        mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not mods & {"subprocess", "socket", "urllib", "requests"}, f.name
        assert not re.search(r"['\"](-X|--method|POST|PATCH|PUT|DELETE)['\"]", src), f.name
        froms = {(n.module or "") for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert not any(m.endswith("repositories") for m in froms), f.name       # the clone module
        assert "clone_or_update" not in src and "git(" not in src, f.name


def test_catalog_file_and_categories(tmp_path):
    specs = load_catalog(Path(__file__).parents[1])
    logins = {s.login.lower() for s in specs}
    assert {"nasa", "cnes", "numerique-gouv", "etalab", "microsoft", "google", "kubernetes", "apache"} <= logins
    assert {s.category for s in specs} <= {"science_agency", "public_admin", "company", "foundation", "community"}


def test_migration_v5_to_v6(tmp_path):
    p = tmp_path / "old.db"
    db = Database(p)
    for t in ("disc_events", "disc_errors", "disc_runs", "disc_repos", "disc_orgs"):
        db.conn.execute(f"DROP TABLE {t}")
    db.conn.execute("UPDATE meta SET value='5' WHERE key='schema_version'")
    db.close()
    db2 = Database(p)
    assert SCHEMA_VERSION >= 6
    assert db2.conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
    assert {"disc_orgs", "disc_repos", "disc_events", "disc_errors", "disc_runs"} <= \
        {r[0] for r in db2.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_cli_json_outputs_offline(tmp_path):
    gh = FakeGitHub(orgs={"acme": {"login": "acme"}}, repos={"acme": [raw_repo(1, "core")]},
                    extra=enrich_responses())
    data = tmp_path / "data"
    data.mkdir()
    db = Database(data / "gsr.db")
    refresh(DiscoveryStore(db), ReadOnlyGitHub(gh, reserve=10), [OrgSpec("acme", "foundation")], now=NOW)
    db.close()
    root = tmp_path / "gsr"
    (root / "config").mkdir(parents=True)
    (root / "config" / "targets.yaml").write_text("targets: []\n")
    (root / "config" / "policies.yaml").write_text("")
    env = {**os.environ, "GSR_ROOT": str(root), "GSR_DATA_DIR": str(data)}

    def cli(*a):
        out = subprocess.run(["github-sec", "discover", *a], capture_output=True, text=True, env=env, timeout=60)
        assert out.returncode == 0, out.stderr
        return out.stdout
    sl = json.loads(cli("shortlist", "--json"))
    assert sl[0]["rank"] == 1 and sl[0]["repository"] == "acme/core" and sl[0]["recommendation"] == "REVIEW"
    assert sl[0]["reasons"] and "missing" in sl[0] and sl[0]["url"] == "https://github.com/acme/core"
    show = json.loads(cli("show", "acme/core"))
    assert show["facts"]["language"]["source"] == "api:orgs/acme/repos" and show["events"][0]["kind"] == "DISCOVERED"
    ok = json.loads(cli("approve", "acme/core", "--reason", "fits"))
    assert ok["human_decision"] == "approved" and "no scan started" in ok["note"]
    assert (root / "config" / "targets.yaml").read_text() == "targets: []\n"
    st = json.loads(cli("stats"))
    assert st["repositories"]["total"] == 1 and st["repositories"]["by_human_decision"] == {"approved": 1}
    assert "No bug has been searched" in cli("shortlist")
