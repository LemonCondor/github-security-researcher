"""SQLite persistence for discovery (tables disc_*). Repositories are deduplicated by GitHub numeric id, so a
rename/transfer updates the row instead of creating a new discovery. Important field changes are logged."""
from __future__ import annotations

import json
import uuid

from ..storage.database import Database, now
from .scoring import score as compute_score

TRACKED = ("archived", "default_branch", "license", "language", "visibility", "disabled", "fork", "mirror_url")


class DiscoveryStore:
    def __init__(self, db: Database):
        self.db = db
        self.conn = db.conn

    # ---- events / errors / runs
    def event(self, subject: str, kind: str, field: str | None = None, old=None, new=None, data=None) -> None:
        self.conn.execute("INSERT INTO disc_events(subject, created_at, kind, field, old_value, new_value, data) "
                          "VALUES (?,?,?,?,?,?,?)", (subject, now(), kind, field,
                                                     None if old is None else json.dumps(old),
                                                     None if new is None else json.dumps(new),
                                                     json.dumps(data or {}, default=str)))

    def error(self, run_id: str | None, scope: str, subject: str, endpoint: str | None, kind: str, msg: str):
        self.conn.execute("INSERT INTO disc_errors(run_id, created_at, scope, subject, endpoint, kind, message) "
                          "VALUES (?,?,?,?,?,?,?)", (run_id, now(), scope, subject, endpoint, kind, msg[:500]))

    def start_run(self, orgs: list[str]) -> str:
        rid = uuid.uuid4().hex[:12]
        self.conn.execute("INSERT INTO disc_runs(id, started_at, status, orgs) VALUES (?,?, 'running', ?)",
                          (rid, now(), json.dumps(orgs)))
        return rid

    def finish_run(self, rid: str, status: str, stats: dict) -> None:
        self.conn.execute("UPDATE disc_runs SET finished_at=?, status=?, stats=? WHERE id=?",
                          (now(), status, json.dumps(stats), rid))

    # ---- organisations
    def upsert_org(self, login: str, category: str, origin: str, discovered_via: str | None = None,
                   **meta) -> bool:
        key = login.lower()
        row = self.conn.execute("SELECT * FROM disc_orgs WHERE login=?", (key,)).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO disc_orgs(login, display_login, category, origin, discovered_via, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?)", (key, login, category, origin, discovered_via, now(), now()))
            self.event(key, "DISCOVERED", data={"origin": origin, "via": discovered_via, "category": category})
        elif origin == "configured" and (row["origin"] != "configured" or row["category"] != category):
            self.conn.execute("UPDATE disc_orgs SET origin='configured', category=?, updated_at=? WHERE login=?",
                              (category, now(), key))
        cols = {k: v for k, v in meta.items() if k in ("display_login", "name", "website", "domain_verified",
                                                         "description", "github_url", "public_repos", "status",
                                                         "verified_at")}
        if cols:
            if "domain_verified" in cols and cols["domain_verified"] is not None:
                cols["domain_verified"] = int(bool(cols["domain_verified"]))
            sets = ", ".join(f"{k}=?" for k in cols)
            self.conn.execute(f"UPDATE disc_orgs SET {sets}, updated_at=? WHERE login=?",
                              (*cols.values(), now(), key))
        return row is None

    def org(self, login: str):
        return self.conn.execute("SELECT * FROM disc_orgs WHERE login=?", (login.lower(),)).fetchone()

    def orgs(self, category: str | None = None) -> list:
        q, args = "SELECT * FROM disc_orgs", []
        if category:
            q += " WHERE category=?"; args.append(category)
        return self.conn.execute(q + " ORDER BY category, login", args).fetchall()

    def explorable(self, row) -> bool:
        return row["review_state"] != "rejected" and (row["origin"] == "configured" or
                                                      row["review_state"] == "approved")

    def set_org_review(self, login: str, state: str, reason: str | None = None) -> None:
        row = self.org(login)
        if row is None:
            raise KeyError(login)
        self.conn.execute("UPDATE disc_orgs SET review_state=?, updated_at=? WHERE login=?",
                          (state, now(), login.lower()))
        self.event(login.lower(), "ORG_REVIEW", "review_state", row["review_state"], state, {"reason": reason})

    # ---- repositories
    def upsert_repo(self, org: str, raw: dict, facts: dict) -> str:
        """Returns 'new' | 'known' | 'renamed'."""
        rid, full = raw["id"], raw["full_name"]
        row = self.conn.execute("SELECT * FROM disc_repos WHERE repo_id=?", (rid,)).fetchone()
        ts = now()
        if row is None:
            self.conn.execute(
                "INSERT INTO disc_repos(repo_id, full_name, display_name, org_login, facts, first_seen, last_checked,"
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (rid, full.lower(), full, org.lower(), json.dumps(facts), ts, ts, ts, ts))
            self.event(full.lower(), "DISCOVERED", data={"repo_id": rid})
            return "new"
        status = "known"
        old = json.loads(row["facts"])
        if row["full_name"] != full.lower():
            self.event(full.lower(), "RENAMED", "full_name", row["full_name"], full.lower())
            status = "renamed"
        for k in TRACKED:
            ov, nv = (old.get(k) or {}).get("value"), (facts.get(k) or {}).get("value")
            if k in facts and k in old and ov != nv:
                self.event(full.lower(), "CHANGED", k, ov, nv)
        merged = {**old, **facts}                      # keep second-pass facts collected earlier
        self.conn.execute("UPDATE disc_repos SET full_name=?, display_name=?, org_login=?, facts=?, last_checked=?,"
                          " updated_at=? WHERE repo_id=?", (full.lower(), full, org.lower(), json.dumps(merged),
                                                           ts, ts, rid))
        return status

    def add_enrichment(self, full: str, facts: dict) -> None:
        row = self.repo(full)
        merged = {**json.loads(row["facts"]), **facts}
        self.conn.execute("UPDATE disc_repos SET facts=?, enriched_at=?, updated_at=? WHERE repo_id=?",
                          (json.dumps(merged), now(), now(), row["repo_id"]))

    def repo(self, full: str):
        return self.conn.execute("SELECT * FROM disc_repos WHERE full_name=?", (full.lower(),)).fetchone()

    def repos(self, org: str | None = None) -> list:
        q, args = "SELECT r.*, o.category FROM disc_repos r JOIN disc_orgs o ON o.login=r.org_login", []
        if org:
            q += " WHERE r.org_login=?"; args.append(org.lower())
        return self.conn.execute(q, args).fetchall()

    def rescore(self, full: str | None = None, max_repo_kb: int | None = None) -> int:
        rows = [self.repo(full)] if full else self.repos()
        n = 0
        for r in rows:
            if r is None:
                continue
            cat = self.conn.execute("SELECT category FROM disc_orgs WHERE login=?", (r["org_login"],)).fetchone()[0]
            s = compute_score(json.loads(r["facts"]), cat, **({"max_repo_kb": max_repo_kb} if max_repo_kb else {}))
            if (r["score"], r["recommendation"], r["score_version"]) != (s["score"], s["recommendation"], s["version"]):
                self.event(r["full_name"], "SCORED", "recommendation", r["recommendation"], s["recommendation"],
                           {"score": s["score"], "version": s["version"]})
            self.conn.execute("UPDATE disc_repos SET score=?, score_version=?, tier=?, recommendation=?, "
                              "justification=?, updated_at=? WHERE repo_id=?",
                              (s["score"], s["version"], s["tier"], s["recommendation"], json.dumps(s), now(),
                               r["repo_id"]))
            n += 1
        return n

    def decide(self, full: str, decision: str, reason: str | None = None) -> None:
        """Human decision only. Approval does NOT add a scan target and does NOT start any scan."""
        if decision not in ("approved", "rejected", "none"):
            raise ValueError(decision)
        row = self.repo(full)
        if row is None:
            raise KeyError(full)
        self.conn.execute("UPDATE disc_repos SET human_decision=?, human_reason=?, decided_at=?, updated_at=? "
                          "WHERE repo_id=?", (decision, reason, now(), now(), row["repo_id"]))
        self.event(row["full_name"], "DECISION", "human_decision", row["human_decision"], decision,
                   {"reason": reason})

    def shortlist(self, org: str | None = None, category: str | None = None, include_excluded: bool = False,
                  limit: int = 25) -> list:
        q = ("SELECT r.*, o.category, o.name AS org_name FROM disc_repos r JOIN disc_orgs o ON o.login=r.org_login "
             "WHERE r.recommendation IS NOT NULL")
        args: list = []
        if org:
            q += " AND r.org_login=?"; args.append(org.lower())
        if category:
            q += " AND o.category=?"; args.append(category)
        if not include_excluded:
            q += " AND r.recommendation<>'EXCLUDE' AND r.human_decision<>'rejected'"
        q += (" ORDER BY CASE r.recommendation WHEN 'REVIEW' THEN 0 WHEN 'DEFER' THEN 1 ELSE 2 END, "
              "r.score DESC, r.full_name LIMIT ?")
        return self.conn.execute(q, (*args, limit)).fetchall()

    def stats(self) -> dict:
        def grp(sql):
            return {k if k is not None else "unscored": v for k, v in self.conn.execute(sql).fetchall()}
        last = self.conn.execute("SELECT * FROM disc_runs ORDER BY started_at DESC LIMIT 1").fetchone()
        return {
            "organisations": {"total": self.conn.execute("SELECT COUNT(*) FROM disc_orgs").fetchone()[0],
                              "by_category": grp("SELECT category, COUNT(*) FROM disc_orgs GROUP BY 1"),
                              "by_origin": grp("SELECT origin, COUNT(*) FROM disc_orgs GROUP BY 1"),
                              "by_review_state": grp("SELECT review_state, COUNT(*) FROM disc_orgs GROUP BY 1"),
                              "by_status": grp("SELECT status, COUNT(*) FROM disc_orgs GROUP BY 1")},
            "repositories": {"total": self.conn.execute("SELECT COUNT(*) FROM disc_repos").fetchone()[0],
                             "enriched": self.conn.execute(
                                 "SELECT COUNT(*) FROM disc_repos WHERE enriched_at IS NOT NULL").fetchone()[0],
                             "by_recommendation": grp("SELECT recommendation, COUNT(*) FROM disc_repos GROUP BY 1"),
                             "by_tier": grp("SELECT tier, COUNT(*) FROM disc_repos GROUP BY 1"),
                             "by_human_decision": grp("SELECT human_decision, COUNT(*) FROM disc_repos GROUP BY 1")},
            "errors": grp("SELECT kind, COUNT(*) FROM disc_errors GROUP BY 1"),
            "last_run": None if last is None else {k: (json.loads(last[k]) if k in ("orgs", "stats") else last[k])
                                                   for k in last.keys()},
        }
