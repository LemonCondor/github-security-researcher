"""D4 audit mapper: relate a DEPLOYED contract version (from D3) to the audit material of its protocol.

Operates on already-extracted document TEXT (no PDF dependency in the core; see extract_pdf_text for an
optional, import-guarded helper). It never crawls the web and never decides a document is official from its
name: association is carried by AuditDocument.origin, set by the caller from where the document was found.

What it determines, with provenance on every conclusion:
  - audited/fix-review refs (commit sha or version tag) EXPLICITLY present in the text (never inferred from a date);
  - which deployed files the documents mention / review / report a finding on / verify a fix for;
  - a coverage status of the DEPLOYED delta: EXPLICIT_DELTA / PRIOR_VERSION_ONLY / PARTIAL / UNKNOWN /
    PRIVATE_UNKNOWN (the last only when a document explicitly signals possible private coverage).

Key rules: a mere mention never becomes REVIEWED; EXPLICIT_DELTA means the delta is identifiable in the docs,
NOT that it was reviewed and judged safe; PRIVATE_UNKNOWN is never produced from the absence of a public report.
"""
from __future__ import annotations

import re

from .models import (AuditCoverage, AuditFinding, AuditRef, COV_PARTIAL, COV_UNKNOWN, CONFLICTING, DOC_FINDING_REPORTED,
                     DOC_FIX_VERIFIED, DOC_MENTIONED, DOC_REVIEWED, DOC_UNKNOWN, EXPLICIT_DELTA, ParsedAudit,
                     PRIOR_VERSION_ONLY, PRIVATE_UNKNOWN, Source, UNKNOWN, VERIFIED)

_SHA = re.compile(r"\b([0-9a-f]{7,40})\b")
_TAG = re.compile(r"\bv\d+\.\d+(?:\.\d+)?\b")
_SOL = re.compile(r"[\w./-]+\.(?:sol|vy)\b")
_FINDING = re.compile(r"\b(?:[HMLQIC]-\d{1,3}|Cantina-\d{4,6}(?:-\d{1,3})?|report\s+\d{4,6}|y\d{1,3})\b", re.I)
_DOC_STATE_ORDER = {DOC_UNKNOWN: 0, DOC_MENTIONED: 1, DOC_REVIEWED: 2, DOC_FINDING_REPORTED: 3, DOC_FIX_VERIFIED: 4}

# Explicit phrases. A scope/review statement is required for REVIEWED; a mention is not enough.
_FIX_RE = re.compile(r"(?:fix(?:es|ed)?\s+(?:were\s+)?(?:assessed|verified|reviewed)\s+at\s+commit|"
                     r"remediation\s+(?:reviewed|verified)\s+at|resolved\s+in\s+commit)\s+([0-9a-f]{7,40})", re.I)
_AUDITED_COMMIT_RE = re.compile(r"(?:audited|reviewed|scope[d]?|assessed)\s+at\s+commit\s+([0-9a-f]{7,40})", re.I)
_PR_AT_RE = re.compile(r"(?:pr-?\d+|pull request #?\d+)\s*@\s*([0-9a-f]{7,40})", re.I)
_SCOPE_LINE_RE = re.compile(r"(?:in scope|scope\s*[:\-]|scope of (?:this|the) (?:review|audit|assessment)|"
                            r"files? (?:in scope|reviewed|assessed|covered)|strictly limited to)", re.I)
_PRIVATE_RE = re.compile(r"(?:private audit|undisclosed|not public|under embargo|internal review only|"
                         r"confidential report)", re.I)


def extract_pdf_text(path: str) -> str:  # pragma: no cover - optional dependency
    """Best-effort PDF text extraction. Import-guarded: pypdf is NOT a hard dependency of GSR."""
    try:
        import pypdf
    except ImportError as e:
        raise ImportError("extract_pdf_text needs pypdf; the audit mapper otherwise works on supplied text") from e
    return "\n".join((p.extract_text() or "") for p in pypdf.PdfReader(path).pages)


def _norm_file(p: str) -> str:
    return p.strip().lstrip("./")


def parse_document(doc) -> ParsedAudit:
    """Extract refs/files/findings/states from one AuditDocument's text. Deterministic; no date->commit guess."""
    text = doc.text or ""
    pa = ParsedAudit(doc_id=doc.doc_id)
    seen_refs: set[tuple] = set()

    def add_ref(kind: str, value: str, role: str, evidence: str):
        key = (kind, value.lower(), role)
        if key not in seen_refs:
            seen_refs.add(key)
            pa.refs.append(AuditRef(kind, value.lower() if kind == "commit" else value, role, doc.doc_id,
                                    evidence[:160]))

    for m in _FIX_RE.finditer(text):
        add_ref("commit", m.group(1), "fix_review", m.group(0))
    for m in _AUDITED_COMMIT_RE.finditer(text):
        add_ref("commit", m.group(1), "audited", m.group(0))
    for m in _PR_AT_RE.finditer(text):
        add_ref("commit", m.group(1), "audited", m.group(0))
    for m in _TAG.finditer(text):
        add_ref("tag", m.group(0), "audited", _line_of(text, m.start()))

    files = {_norm_file(m.group(0)) for m in _SOL.finditer(text)}
    pa.files = sorted(files)

    # Reviewed files: only those named on an explicit scope/review line.
    reviewed: set[str] = set()
    for line in text.splitlines():
        if _SCOPE_LINE_RE.search(line):
            reviewed.update(_norm_file(m.group(0)) for m in _SOL.finditer(line))
    # a scope statement may be followed by a bulleted file list: capture .sol lines right after a scope line
    reviewed.update(_scope_block_files(text))
    pa.reviewed_files = sorted(reviewed)

    fix_commit_files: set[str] = set()
    for m in _FINDING.finditer(text):
        line = _line_of(text, m.start())
        ffiles = [_norm_file(x.group(0)) for x in _SOL.finditer(line)]
        state = DOC_FIX_VERIFIED if _FIX_RE.search(line) else DOC_FINDING_REPORTED
        pa.findings.append(AuditFinding(ident=m.group(0), doc_id=doc.doc_id, files=ffiles, state=state,
                                        evidence=line.strip()[:160]))
        if state == DOC_FIX_VERIFIED:
            fix_commit_files.update(ffiles)

    pa.signals_private = bool(_PRIVATE_RE.search(text))

    states: dict[str, str] = {}
    for f in pa.files:
        states[f] = DOC_MENTIONED
    for f in reviewed:
        states[f] = _stronger(states.get(f, DOC_UNKNOWN), DOC_REVIEWED)
    for fnd in pa.findings:
        for f in fnd.files:
            states[f] = _stronger(states.get(f, DOC_UNKNOWN), fnd.state)
    pa.file_states = states
    return pa


def _line_of(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start:(end if end != -1 else len(text))]


def _scope_block_files(text: str) -> set[str]:
    """.sol files on the lines immediately following an explicit scope statement (a bulleted scope list)."""
    out: set[str] = set()
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not _SCOPE_LINE_RE.search(line):
            continue
        for nxt in lines[i + 1:i + 12]:
            sols = [_norm_file(m.group(0)) for m in _SOL.finditer(nxt)]
            if sols:
                out.update(sols)
            elif nxt.strip() and not nxt.lstrip().startswith(("-", "*", "•", "·")) and ":" not in nxt:
                break   # left the scope block
    return out


def _stronger(a: str, b: str) -> str:
    return a if _DOC_STATE_ORDER[a] >= _DOC_STATE_ORDER[b] else b


def _semver(tag: str) -> tuple | None:
    m = re.fullmatch(r"v(\d+)\.(\d+)(?:\.(\d+))?", tag)
    return tuple(int(x or 0) for x in m.groups()) if m else None


def map_coverage(version_match, deployed_files: list[str], documents: list) -> AuditCoverage:
    """Combine the D3 VersionMatch (deployed ref + its source files) with parsed audit documents."""
    vm = version_match
    deployed_files = [_norm_file(f) for f in deployed_files]
    parsed = [parse_document(d) for d in documents]
    by_id = {d.doc_id: d for d in documents}
    ts = vm.sources[0].observed_at if getattr(vm, "sources", None) else ""
    sources = [Source("audit_doc", f"{d.origin}:{d.location}#sha256={d.sha256}", ts,
                      detail=f"date={d.date} auditor={d.auditor}") for d in documents]

    cov = AuditCoverage(chain_id=vm.chain_id, address=vm.address, deployed_ref=vm.ref, status=COV_UNKNOWN,
                        doc_state=DOC_UNKNOWN, certainty=VERIFIED, sources=sources)
    if not documents:
        cov.justification = ["no audit document was associated with this target"]
        return cov

    # Aggregate documentary state per deployed file (strongest across documents), with provenance.
    file_state: dict[str, str] = {}
    for pa in parsed:
        for f, st in pa.file_states.items():
            if f in deployed_files:
                file_state[f] = _stronger(file_state.get(f, DOC_UNKNOWN), st)
    cov.covered_files = sorted(f for f in deployed_files if file_state.get(f, DOC_UNKNOWN) != DOC_UNKNOWN)
    cov.uncovered_files = sorted(f for f in deployed_files if f not in cov.covered_files)
    cov.doc_state = max((file_state.get(f, DOC_UNKNOWN) for f in deployed_files), key=lambda s: _DOC_STATE_ORDER[s],
                        default=DOC_UNKNOWN)

    audited_refs = [r for pa in parsed for r in pa.refs]
    cov.audited_refs = sorted({f"{r.kind}:{r.value}" for r in audited_refs})
    for r in audited_refs:
        cov.justification.append(f"{r.role} {r.kind} {r.value} [{by_id[r.doc_id].origin}: {r.evidence}]")

    deployed_ref_val = _ref_value(vm.ref)
    explicit = _explicit_delta_refs(deployed_ref_val, audited_refs)
    if explicit:
        cov.status, cov.method = EXPLICIT_DELTA, "audited ref equals the deployed ref"
        cov.justification.insert(0, f"deployed ref {vm.ref} explicitly present in audit docs: {explicit}")
        if len({r for r in explicit}) > 1 and _conflict(explicit):
            cov.status, cov.certainty = CONFLICTING, CONFLICTING
        return cov

    prior = _prior_only(deployed_ref_val, audited_refs)
    if cov.covered_files and len(cov.uncovered_files) and cov.status == COV_UNKNOWN:
        partial = True
    else:
        partial = False

    if prior:
        cov.status, cov.method = PRIOR_VERSION_ONLY, "audited version strictly precedes the deployed version"
        cov.justification.insert(0, f"audited {prior} < deployed {deployed_ref_val}")
    elif partial:
        cov.status = COV_PARTIAL
        cov.justification.insert(0, f"{len(cov.covered_files)}/{len(deployed_files)} deployed files appear in docs")
    else:
        cov.status = COV_UNKNOWN
        cov.justification.insert(0, "no exploitable ref/version correspondence between docs and the deployed version")

    # PRIVATE_UNKNOWN only when a document explicitly signals possible private coverage, and we otherwise know little.
    if any(pa.signals_private for pa in parsed) and cov.status in (COV_UNKNOWN, PRIOR_VERSION_ONLY):
        cov.status = PRIVATE_UNKNOWN
        cov.justification.insert(0, "a document explicitly signals possible private/undisclosed coverage")
    return cov


def _ref_value(ref: str | None) -> str | None:
    if not ref:
        return None
    return ref.rsplit("@", 1)[-1].strip().lower()


def _explicit_delta_refs(deployed: str | None, refs: list) -> list[str]:
    if not deployed:
        return []
    out = []
    for r in refs:
        v = r.value.lower()
        if v == deployed or (len(deployed) >= 7 and len(v) >= 7 and (deployed.startswith(v) or v.startswith(deployed))
                             and r.kind == "commit"):
            out.append(f"{r.kind}:{r.value}")
    return sorted(set(out))


def _prior_only(deployed: str | None, refs: list) -> str | None:
    """Only when both are semver tags and the audited one is strictly lower. SHA ancestry is never guessed."""
    if not deployed:
        return None
    dep = _semver(deployed if deployed.startswith("v") else "v" + deployed)
    if dep is None:
        return None
    lowers = [r.value for r in refs if r.kind == "tag" and (_semver(r.value) or (0,)) < dep]
    equal_or_higher = [r.value for r in refs if r.kind == "tag" and _semver(r.value) and _semver(r.value) >= dep]
    if lowers and not equal_or_higher:
        return max(lowers, key=lambda t: _semver(t))
    return None


def _conflict(refs: list[str]) -> bool:
    commits = {r.split(":", 1)[1] for r in refs if r.startswith("commit:")}
    return len(commits) > 1
