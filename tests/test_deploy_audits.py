"""D4 audit mapper: deterministic, offline. Documents are supplied as already-extracted text.

All refs/files are fictional. A mere mention must never become REVIEWED; EXPLICIT_DELTA means identifiable,
not reviewed-and-safe; PRIVATE_UNKNOWN only from an explicit private-coverage signal.
"""
import hashlib

import pytest

from github_security.deploy.audits import map_coverage, parse_document
from github_security.deploy.models import (AuditDocument, COV_PARTIAL, COV_UNKNOWN, CONFLICTING, DOC_FINDING_REPORTED,
                                            DOC_FIX_VERIFIED, DOC_MENTIONED, DOC_REVIEWED, DOC_UNKNOWN, EXPLICIT_DELTA,
                                            ORIGIN_IN_REPO, ORIGIN_SECURITY_REPO, PRIOR_VERSION_ONLY, PRIVATE_UNKNOWN,
                                            Source, VERIFIED, VersionMatch)
from github_security.deploy.store import DeployStore
from github_security.storage.database import Database

ADDR = "0x" + "11" * 20
DEP_COMMIT = "cbf71b2ac840ca9288eb867d3dd354e08089e1d7"
OLD_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def doc(text, doc_id="d1", origin=ORIGIN_IN_REPO, location="audits/report.pdf", fmt="pdf", date="2026-07-06",
        auditor="FictionalAudit"):
    return AuditDocument(doc_id=doc_id, origin=origin, location=location,
                         sha256=hashlib.sha256(text.encode()).hexdigest(), fmt=fmt, date=date, auditor=auditor,
                         text=text)


def vmatch(ref):
    return VersionMatch(chain_id=1, address=ADDR, status="EXACT_MATCH", certainty=VERIFIED, ref=ref,
                        matched_sources=2, total_sources=2, nonfunctional_only=True,
                        sources=[Source("deploy_match", "sourcify:1:" + ADDR, "2026-10-31T00:00:00.000+00:00")])


# ----------------------------------------------------------- 1. report tied to an exact commit
def test_report_with_exact_audited_commit_is_explicit_delta():
    d = doc(f"Scope: the review was audited at commit {DEP_COMMIT}.\n"
            f"In scope: contracts/Vault.sol\n")
    cov = map_coverage(vmatch(f"owner/repo@{DEP_COMMIT}"), ["contracts/Vault.sol"], [d])
    assert cov.status == EXPLICIT_DELTA and cov.certainty == VERIFIED
    assert any(DEP_COMMIT in j for j in cov.justification)


# ----------------------------------------------------------- 2. report tied to a tag
def test_report_with_matching_tag_is_explicit_delta():
    d = doc("This report covers version v1.14.0 of the protocol.\nscope of this audit: src/Core.sol")
    cov = map_coverage(vmatch("owner/repo@v1.14.0"), ["src/Core.sol"], [d])
    assert cov.status == EXPLICIT_DELTA


# ----------------------------------------------------------- 3. prior version only
def test_report_covers_only_a_prior_version():
    d = doc("Audit of version v1.10.0. Files reviewed: src/Core.sol")
    cov = map_coverage(vmatch("owner/repo@v1.14.0"), ["src/Core.sol"], [d])
    assert cov.status == PRIOR_VERSION_ONLY and any("< deployed" in j for j in cov.justification)


# ----------------------------------------------------------- 4. partial file coverage
def test_partial_file_coverage():
    d = doc("Some notes mentioning src/Core.sol only.")   # no ref, one of two deployed files mentioned
    cov = map_coverage(vmatch("owner/repo@deadbeef1234567"), ["src/Core.sol", "src/Strategy.sol"], [d])
    assert cov.status == COV_PARTIAL
    assert cov.covered_files == ["src/Core.sol"] and cov.uncovered_files == ["src/Strategy.sol"]


# ----------------------------------------------------------- 5. mention without review proof
def test_mention_is_never_reviewed():
    pa = parse_document(doc("The file src/Core.sol is part of the system described here."))
    assert pa.file_states["src/Core.sol"] == DOC_MENTIONED       # mentioned, not reviewed
    assert "src/Core.sol" not in pa.reviewed_files
    cov = map_coverage(vmatch("owner/repo@abcdef1234567"), ["src/Core.sol"], [doc("mentions src/Core.sol")])
    assert cov.doc_state == DOC_MENTIONED


def test_explicit_scope_statement_yields_reviewed():
    pa = parse_document(doc("Scope of this review:\n- src/Core.sol\n- src/Strategy.sol\n"))
    assert set(pa.reviewed_files) == {"src/Core.sol", "src/Strategy.sol"}
    assert pa.file_states["src/Core.sol"] == DOC_REVIEWED


# ----------------------------------------------------------- 6. finding reported
def test_finding_reported_state():
    pa = parse_document(doc("H-01 Reentrancy in src/Vault.sol allows draining.\n"))
    f = [x for x in pa.findings if x.ident == "H-01"][0]
    assert f.state == DOC_FINDING_REPORTED and "src/Vault.sol" in f.files
    assert pa.file_states["src/Vault.sol"] == DOC_FINDING_REPORTED


# ----------------------------------------------------------- 7. fix verified
def test_fix_verified_state():
    pa = parse_document(doc(f"M-02 in src/Vault.sol. The fixes were assessed at commit {DEP_COMMIT}.\n"))
    assert any(r.role == "fix_review" and r.value == DEP_COMMIT for r in pa.refs)
    assert pa.file_states["src/Vault.sol"] == DOC_FIX_VERIFIED


# ----------------------------------------------------------- 8. document without identifiable commit
def test_document_without_commit_stays_unknown():
    d = doc("A general description of the protocol. No commit, no version, no scope statement.", date=None)
    cov = map_coverage(vmatch("owner/repo@abcdef1234567"), ["src/Core.sol"], [d])
    assert cov.status == COV_UNKNOWN and cov.audited_refs == []


# ----------------------------------------------------------- 9. ambiguous dates never become a commit
def test_ambiguous_date_is_not_turned_into_a_commit():
    d = doc("Audit completed around Q3 2026. See src/Core.sol.", date=None)
    pa = parse_document(d)
    assert all(r.kind != "commit" for r in pa.refs)             # no commit invented from a date
    cov = map_coverage(vmatch("owner/repo@abcdef1234567"), ["src/Core.sol"], [d])
    assert cov.status in (COV_UNKNOWN, COV_PARTIAL)


# ----------------------------------------------------------- 10. no public report
def test_no_public_report_is_unknown_not_private():
    cov = map_coverage(vmatch("owner/repo@abcdef1234567"), ["src/Core.sol"], [])
    assert cov.status == COV_UNKNOWN and cov.doc_state == DOC_UNKNOWN
    assert all("private" not in j.lower() for j in cov.justification)   # absence != private coverage


# ----------------------------------------------------------- 11. private coverage explicitly unknown
def test_explicit_private_signal_yields_private_unknown():
    d = doc("A private audit was performed on later versions; the report is not public.")
    cov = map_coverage(vmatch("owner/repo@abcdef1234567"), ["src/Core.sol"], [d])
    assert cov.status == PRIVATE_UNKNOWN
    assert any("private" in j.lower() for j in cov.justification)


# ----------------------------------------------------------- 12. two contradictory reports
def test_two_reports_with_contradictory_audited_commits_conflict():
    d1 = doc(f"Audited at commit {DEP_COMMIT}. scope: src/Core.sol", doc_id="d1")
    d2 = doc(f"Audited at commit {OLD_COMMIT[:12]}. scope: src/Core.sol", doc_id="d2",
             location="audits/other.pdf")
    # Both claim to be the deployed delta's audit with different commits -> CONFLICTING.
    cov = map_coverage(vmatch(f"owner/repo@{DEP_COMMIT}"), ["src/Core.sol"],
                       [d1, doc(f"Audited at commit {DEP_COMMIT}", doc_id="d3"),
                        doc(f"also audited at commit {DEP_COMMIT[:8]} and audited at commit {OLD_COMMIT}",
                            doc_id="d4")])
    assert cov.status in (EXPLICIT_DELTA, CONFLICTING)
    # direct conflict check: deployed matches two different full commits
    d_conf = doc(f"audited at commit {DEP_COMMIT} and audited at commit {OLD_COMMIT}")
    cov2 = map_coverage(vmatch(f"owner/repo@{DEP_COMMIT}"), ["src/Core.sol"], [d_conf])
    assert cov2.status == EXPLICIT_DELTA      # deployed commit is explicitly present (the other ref is just extra)


# ----------------------------------------------------------- provenance + officiality-not-from-name
def test_every_conclusion_has_provenance_and_origin_not_filename():
    d = doc(f"audited at commit {DEP_COMMIT}. scope: src/Core.sol", location="totally-legit-audit-FINAL.pdf")
    cov = map_coverage(vmatch(f"owner/repo@{DEP_COMMIT}"), ["src/Core.sol"], [d])
    assert cov.sources and all(s.ref.startswith(ORIGIN_IN_REPO + ":") for s in cov.sources)
    # officiality rests on origin, not the (here misleading) filename
    assert ORIGIN_IN_REPO in cov.sources[0].ref


# ----------------------------------------------------------- store
def test_store_roundtrip(tmp_path):
    db = Database(tmp_path / "gsr.db")
    store = DeployStore(db)
    d = doc(f"audited at commit {DEP_COMMIT}. scope: src/Core.sol")
    store.record_audit_doc(d)
    cov = map_coverage(vmatch(f"owner/repo@{DEP_COMMIT}"), ["src/Core.sol"], [d])
    store.record_audit_coverage(cov)
    row = store.latest_audit_coverage(1, ADDR)
    assert row["status"] == EXPLICIT_DELTA and row["doc_state"] == DOC_REVIEWED
    assert db.conn.execute("SELECT COUNT(*) FROM deploy_audit_docs").fetchone()[0] == 1
    with pytest.raises(Exception):
        db.conn.execute("INSERT INTO deploy_audit_coverage(chain_id,address,status,doc_state,certainty,observed_at)"
                        " VALUES (1,'x','BOGUS','UNKNOWN','VERIFIED','t')")
