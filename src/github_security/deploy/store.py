"""SQLite persistence for the deployment mapper (tables deploy_*). Same shape as DiscoveryStore.

Programs/assets are upserted (the scope snapshot is replaced by the latest one, its sha256 is kept).
Deployment observations and proxy relationships are append-only: an upgrade observed at a later block adds rows.
"""
from __future__ import annotations

import json

from ..storage.database import Database, now
from .models import MappingResult, ScopeAsset, Source
from .scope import ProgramScope


def _sources(srcs: list[Source]) -> str:
    return json.dumps([s.as_dict() for s in srcs])


def _bool(v: bool | None) -> int | None:
    return None if v is None else int(v)


class DeployStore:
    def __init__(self, db: Database):
        self.db = db
        self.conn = db.conn

    def upsert_program(self, scope: ProgramScope) -> int:
        self.conn.execute(
            "INSERT INTO deploy_programs(platform, slug, name, max_bounty, kyc, scope_sha256, scope_complete,"
            " source_url, fetched_at) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(platform, slug) DO UPDATE SET name=excluded.name, max_bounty=excluded.max_bounty,"
            " kyc=excluded.kyc, scope_sha256=excluded.scope_sha256, scope_complete=excluded.scope_complete,"
            " source_url=excluded.source_url, fetched_at=excluded.fetched_at",
            (scope.platform, scope.slug, scope.name, scope.max_bounty, _bool(scope.kyc), scope.scope_sha256,
             int(scope.complete), scope.source_url, scope.fetched_at))
        pid = self.conn.execute("SELECT id FROM deploy_programs WHERE platform=? AND slug=?",
                                (scope.platform, scope.slug)).fetchone()[0]
        for a in scope.assets:
            self._upsert_asset(pid, a)
        return pid

    def _upsert_asset(self, program_id: int, a: ScopeAsset) -> None:
        self.conn.execute(
            "INSERT INTO deploy_assets(program_id, key, asset_kind, chain_id, address, names, urls, added_at,"
            " is_primacy_of_impact, chain_certainty, certainty, sources, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(program_id, key) DO UPDATE SET asset_kind=excluded.asset_kind, names=excluded.names,"
            " urls=excluded.urls, added_at=excluded.added_at, is_primacy_of_impact=excluded.is_primacy_of_impact,"
            " chain_certainty=excluded.chain_certainty, certainty=excluded.certainty, sources=excluded.sources,"
            " updated_at=excluded.updated_at",
            (program_id, a.key, a.asset_kind, a.chain_id, a.address, json.dumps(a.names), json.dumps(a.urls),
             a.added_at, _bool(a.is_primacy_of_impact), a.chain_certainty, a.certainty, _sources(a.sources), now()))

    def asset_id(self, program_id: int, key: str | None) -> int | None:
        if key is None:
            return None
        row = self.conn.execute("SELECT id FROM deploy_assets WHERE program_id=? AND key=?",
                                (program_id, key)).fetchone()
        return row[0] if row else None

    def record(self, program_id: int, r: MappingResult) -> int:
        ts = now()
        cur = self.conn.execute(
            "INSERT INTO deploy_deployments(asset_id, chain_id, address, block, status, kind, code_size, code_sha256,"
            " certainty, reasons, sources, observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.asset_id(program_id, r.asset_key), r.chain_id, r.address, r.block, r.status, r.kind, r.code_size,
             r.code_sha256, r.certainty, json.dumps(r.reasons), _sources(r.sources), ts))
        dep_id = cur.lastrowid
        if r.proxy is not None:
            p = r.proxy
            self.conn.execute(
                "INSERT INTO deploy_proxies(deployment_id, standard, resolution, implementation,"
                " implementation_has_code, beacon, admin, certainty, sources, observed_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (dep_id, p.standard, p.resolution, p.implementation, _bool(p.implementation_has_code), p.beacon,
                 p.admin, p.certainty, _sources(p.sources), ts))
        return dep_id

    def latest(self, chain_id: int, address: str):
        return self.conn.execute(
            "SELECT d.*, p.standard, p.resolution, p.implementation, p.implementation_has_code"
            " FROM deploy_deployments d LEFT JOIN deploy_proxies p ON p.deployment_id = d.id"
            " WHERE d.chain_id=? AND d.address=? ORDER BY d.id DESC LIMIT 1",
            (chain_id, address.lower())).fetchone()

    def record_version_match(self, vc, vm) -> int:
        """Persist one VersionMatch (D3). vc provides provider/runtime_match/compiler for provenance."""
        cur = self.conn.execute(
            "INSERT INTO deploy_version_matches(chain_id, address, provider, status, ref, matched_sources,"
            " total_sources, nonfunctional_only, runtime_match, compiler, compiler_version, certainty, evidence,"
            " sources, observed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (vm.chain_id, vm.address, vc.provider, vm.status, vm.ref, vm.matched_sources, vm.total_sources,
             _bool(vm.nonfunctional_only), vc.runtime_match, vc.compiler, vc.compiler_version, vm.certainty,
             json.dumps(vm.evidence), _sources(vm.sources), now()))
        return cur.lastrowid

    def latest_version_match(self, chain_id: int, address: str):
        return self.conn.execute(
            "SELECT * FROM deploy_version_matches WHERE chain_id=? AND address=? ORDER BY id DESC LIMIT 1",
            (chain_id, address.lower())).fetchone()

    def record_audit_doc(self, doc) -> None:
        self.conn.execute(
            "INSERT INTO deploy_audit_docs(doc_id, origin, location, sha256, fmt, date, auditor, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(doc_id) DO UPDATE SET origin=excluded.origin, location=excluded.location,"
            " sha256=excluded.sha256, fmt=excluded.fmt, date=excluded.date, auditor=excluded.auditor",
            (doc.doc_id, doc.origin, doc.location, doc.sha256, doc.fmt, doc.date, doc.auditor, now()))

    def record_audit_coverage(self, cov) -> int:
        cur = self.conn.execute(
            "INSERT INTO deploy_audit_coverage(chain_id, address, deployed_ref, status, doc_state, audited_refs,"
            " covered_files, uncovered_files, method, certainty, justification, sources, observed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (cov.chain_id, cov.address, cov.deployed_ref, cov.status, cov.doc_state, json.dumps(cov.audited_refs),
             json.dumps(cov.covered_files), json.dumps(cov.uncovered_files), cov.method, cov.certainty,
             json.dumps(cov.justification), _sources(cov.sources), now()))
        return cur.lastrowid

    def latest_audit_coverage(self, chain_id: int, address: str):
        return self.conn.execute(
            "SELECT * FROM deploy_audit_coverage WHERE chain_id=? AND address=? ORDER BY id DESC LIMIT 1",
            (chain_id, address.lower())).fetchone()

    def record_triage_candidate(self, tc) -> int:
        import json as _json
        funds = tc.deltas and min((d.funds for d in tc.deltas), key=lambda f: 0 if f == "DIRECT_USER_FUNDS_PATH"
                                  else (1 if f == "UNKNOWN" else 2)) or "UNKNOWN"
        deltas = [{"function": d.function, "change": d.change, "categories": d.categories, "funds": d.funds,
                   "evidence": d.evidence} for d in tc.deltas]
        cur = self.conn.execute(
            "INSERT INTO deploy_triage_candidates(chain_id, address, file, audited_ref, deployed_ref, status,"
            " categories, funds, score, rank, stop_reasons, certainty, deltas, justification, sources, observed_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (tc.chain_id, tc.address, tc.file, tc.audited_ref, tc.deployed_ref, tc.status,
             _json.dumps(tc.categories), funds, tc.score, _json.dumps(tc.rank.as_dict()),
             _json.dumps(tc.stop_reasons), tc.certainty, _json.dumps(deltas), _json.dumps(tc.justification),
             _sources(tc.sources), now()))
        return cur.lastrowid

    def triage_candidates(self, status: str | None = None):
        if status:
            return self.conn.execute("SELECT * FROM deploy_triage_candidates WHERE status=? ORDER BY score DESC",
                                     (status,)).fetchall()
        return self.conn.execute("SELECT * FROM deploy_triage_candidates ORDER BY score DESC").fetchall()
