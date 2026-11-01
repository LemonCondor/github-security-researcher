"""Typed facts of the deployment mapper. Every fact carries its certainty and its sources.

Certainty is about what we OBSERVED, never about safety:
  VERIFIED     read directly (RPC at a pinned block, official scope snapshot) and internally consistent
  INFERRED     derived from an indirect signal (e.g. chain id guessed from an explorer host)
  UNKNOWN      we could not establish it (read failed, data missing, unsupported mechanism) -- never a negative
  CONFLICTING  two sources disagree; nothing downstream may treat it as established
"""
from __future__ import annotations

from dataclasses import dataclass, field

VERIFIED = "VERIFIED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"
CONFLICTING = "CONFLICTING"
CERTAINTIES = (VERIFIED, INFERRED, UNKNOWN, CONFLICTING)

# Mapping outcome for one (chain, address)
MAPPED = "MAPPED"                  # code read and classified (kind may still be UNKNOWN/UNSUPPORTED)
NOT_IN_SCOPE = "NOT_IN_SCOPE"      # not listed in the program scope snapshot: never read
NOT_DEPLOYED = "NOT_DEPLOYED"      # no runtime code at the pinned block
CHAIN_UNKNOWN = "CHAIN_UNKNOWN"    # network cannot be determined without guessing
WRONG_NETWORK = "WRONG_NETWORK"    # RPC chain id differs from the asset's network
NO_RPC = "NO_RPC"                  # no endpoint configured for that network
RPC_ERROR = "RPC_ERROR"            # a read failed: nothing concluded
STATUSES = (MAPPED, NOT_IN_SCOPE, NOT_DEPLOYED, CHAIN_UNKNOWN, WRONG_NETWORK, NO_RPC, RPC_ERROR)

# Contract kinds supported by this version
DIRECT = "DIRECT"                        # runtime code has no DELEGATECALL/CALLCODE and no proxy slot is set
PROXY_EIP1967 = "PROXY_EIP1967"          # EIP-1967 implementation slot set (transparent or UUPS)
UNSUPPORTED = "UNSUPPORTED"              # a delegating mechanism we recognise but do not resolve in this version
KIND_UNKNOWN = "UNKNOWN"                 # cannot be classified without guessing
KINDS = (DIRECT, PROXY_EIP1967, UNSUPPORTED, KIND_UNKNOWN)

# Proxy -> implementation resolution
RESOLVED = "RESOLVED"                          # implementation address read and has code
IMPLEMENTATION_NO_CODE = "IMPLEMENTATION_NO_CODE"  # slot points to an address without code
AMBIGUOUS = "AMBIGUOUS"                        # several mechanisms set at once
NOT_RESOLVED = "NOT_RESOLVED"                  # recognised mechanism, resolution unsupported in this version
RESOLUTIONS = (RESOLVED, IMPLEMENTATION_NO_CODE, AMBIGUOUS, NOT_RESOLVED)


@dataclass(frozen=True)
class Source:
    """Where a fact comes from. RPC sources keep only scheme+host (URLs can embed API keys)."""
    method: str                      # immunefi_scope | rpc:eth_getCode | rpc:eth_getStorageAt | explorer_host ...
    ref: str                         # scope URL+sha256, RPC host, explorer host...
    observed_at: str
    block: int | None = None
    detail: str = ""

    def as_dict(self) -> dict:
        d = {"method": self.method, "ref": self.ref, "observed_at": self.observed_at}
        if self.block is not None:
            d["block"] = self.block
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class ScopeAsset:
    key: str                         # "<chain_id or ?>:<address>" or the raw URL for non-address assets
    asset_kind: str                  # contract | source_reference | non_contract | incomplete
    chain_id: int | None
    address: str | None              # lowercase 0x-hex, or None
    names: list[str]
    urls: list[str]
    added_at: str | None
    is_primacy_of_impact: bool | None
    chain_certainty: str             # INFERRED from explorer host, UNKNOWN if host not recognised
    certainty: str
    sources: list[Source] = field(default_factory=list)


@dataclass
class ProxyRelationship:
    standard: str                    # EIP1967 | EIP1967_BEACON | EIP1167 | LEGACY_ZOS | MULTIPLE
    resolution: str
    implementation: str | None
    implementation_has_code: bool | None
    beacon: str | None
    admin: str | None
    certainty: str
    sources: list[Source] = field(default_factory=list)


@dataclass
class MappingResult:
    chain_id: int | None
    address: str | None
    status: str
    kind: str | None
    certainty: str
    block: int | None = None
    code_size: int | None = None
    code_sha256: str | None = None
    reasons: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)
    proxy: ProxyRelationship | None = None
    asset_key: str | None = None


# ---- D3: verified source <-> git version matching -------------------------------------------------
# Deployed-bytecode <-> source link comes from Sourcify (it verified it); we do NOT recompile.
# Source <-> git ref link is computed here by keccak256 of file CONTENT (path-independent), which is
# exactly what solc stores in metadata.sources[*].keccak256.
EXACT_MATCH = "EXACT_MATCH"            # Sourcify runtime exact_match AND every compilation source is keccak-present at the ref
COMPILER_MATCH = "COMPILER_MATCH"      # sources all present at the ref, but bytecode matches only modulo metadata (Sourcify 'match')
PARTIAL_MATCH = "PARTIAL_MATCH"        # some sources present at the ref, some missing: not a full correspondence
SOURCE_UNVERIFIED = "SOURCE_UNVERIFIED"  # the explorer has no verified source for this address
NO_GIT_MATCH = "NO_GIT_MATCH"          # source verified, but no candidate ref carries these sources (NOT "new/unaudited")
MATCH_STATUSES = (EXACT_MATCH, COMPILER_MATCH, PARTIAL_MATCH, SOURCE_UNVERIFIED, NO_GIT_MATCH, CONFLICTING, UNKNOWN)

# Bytecode transformation reasons that are NEVER functional code changes (Sourcify vocabulary).
NONFUNCTIONAL_REASONS = frozenset({"cborAuxdata", "library", "immutable", "constructorArguments", "callProtection"})


@dataclass
class VerifiedContract:
    chain_id: int
    address: str
    provider: str                       # "sourcify"
    runtime_match: str | None           # exact_match | match | None
    creation_match: str | None
    verified_at: str | None
    compiler: str | None                # "solc" | "vyper" ...
    compiler_version: str | None
    compiler_settings: dict             # optimizer, viaIR, remappings, libraries, ...
    source_keccaks: dict                # path -> "0x..." keccak256 of the source content (from metadata)
    sources_present: set                # paths for which Sourcify returned content
    runtime_transform_reasons: set      # reasons present in runtimeBytecode.transformations
    linked_libraries: dict              # fqname -> address (transformationValues.libraries)
    has_immutables: bool
    metadata_present: bool
    certainty: str
    sources: list[Source] = field(default_factory=list)


@dataclass
class SourceGitMatch:
    ref: str
    matched: list[str]                  # compilation source paths found (by content keccak) at the ref
    missing: list[str]                  # compilation source paths NOT found at the ref
    total: int

    @property
    def all_present(self) -> bool:
        return self.total > 0 and not self.missing

    @property
    def any_present(self) -> bool:
        return bool(self.matched)


@dataclass
class VersionMatch:
    chain_id: int
    address: str
    status: str
    certainty: str
    ref: str | None                     # the git ref this verdict is about (best candidate), or None
    matched_sources: int = 0
    total_sources: int = 0
    nonfunctional_only: bool | None = None   # True if the only deployed/ref differences are non-functional
    evidence: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)


# ---- D4: audit mapper -----------------------------------------------------------------------------
# How a document was ASSOCIATED with the target. This is the evidence of officiality, never the file name.
ORIGIN_IN_REPO = "in_repo_audits_dir"          # file under the protocol repo's audits/ directory
ORIGIN_SECURITY_REPO = "referenced_security_repo"  # a security repo the program/docs explicitly reference
ORIGIN_PROGRAM_PAGE = "program_page"           # listed on the official bug-bounty program page
ORIGIN_COMMIT_REF = "commit_reference"         # a commit message in the protocol repo references the audit/finding
ORIGINS = (ORIGIN_IN_REPO, ORIGIN_SECURITY_REPO, ORIGIN_PROGRAM_PAGE, ORIGIN_COMMIT_REF)

# Documentary state of ONE file/contract within the audit material. Kept separate from coverage status.
DOC_MENTIONED = "MENTIONED"                     # the file/contract/commit appears in a document
DOC_REVIEWED = "REVIEWED"                        # an explicit scope/"files reviewed" statement includes it
DOC_FINDING_REPORTED = "FINDING_REPORTED"        # a finding entry references it
DOC_FIX_VERIFIED = "FIX_VERIFIED"                # an explicit "fix assessed/verified at <ref>" references it
DOC_UNKNOWN = "UNKNOWN"
DOC_STATES = (DOC_MENTIONED, DOC_REVIEWED, DOC_FINDING_REPORTED, DOC_FIX_VERIFIED, DOC_UNKNOWN)

# Coverage of the DEPLOYED delta by the audit material.
EXPLICIT_DELTA = "EXPLICIT_DELTA"                # the deployed version/delta is explicitly identifiable in the docs
PRIOR_VERSION_ONLY = "PRIOR_VERSION_ONLY"        # docs cover only a version strictly before the deployed one
COV_PARTIAL = "PARTIAL"                          # some deployed files covered, some not
COV_UNKNOWN = "UNKNOWN"                          # no exploitable ref/version correspondence
PRIVATE_UNKNOWN = "PRIVATE_UNKNOWN"              # a document explicitly signals possible private/undisclosed coverage
COVERAGE_STATUSES = (EXPLICIT_DELTA, PRIOR_VERSION_ONLY, COV_PARTIAL, COV_UNKNOWN, PRIVATE_UNKNOWN, CONFLICTING)


@dataclass
class AuditDocument:
    doc_id: str
    origin: str                          # one of ORIGINS -- the association evidence, never the filename
    location: str                        # repo path or URL
    sha256: str
    fmt: str                             # pdf | markdown | text | commit
    date: str | None                     # ISO date if unambiguously stated, else None
    auditor: str | None                  # parsed hint only; never used to assert officiality
    text: str = ""                       # already-extracted text (mapper never executes anything)


@dataclass
class AuditFinding:
    ident: str                           # e.g. "H-01", "Cantina-261005-4", "report 57587"
    doc_id: str
    files: list[str] = field(default_factory=list)
    state: str = DOC_MENTIONED           # FINDING_REPORTED / FIX_VERIFIED when the text proves it
    evidence: str = ""                   # the matched line (provenance)


@dataclass
class AuditRef:
    kind: str                            # "commit" | "tag" | "version"
    value: str
    role: str                            # "audited" | "fix_review"
    doc_id: str
    evidence: str = ""


@dataclass
class ParsedAudit:
    doc_id: str
    refs: list[AuditRef] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    findings: list[AuditFinding] = field(default_factory=list)
    reviewed_files: list[str] = field(default_factory=list)   # only from an explicit scope statement
    signals_private: bool = False        # a document explicitly flags possible private/undisclosed coverage
    file_states: dict = field(default_factory=dict)           # file -> highest DOC_* proven by this document


@dataclass
class AuditCoverage:
    chain_id: int
    address: str
    deployed_ref: str | None
    status: str                          # COVERAGE_STATUSES
    doc_state: str                       # DOC_STATES: strongest documentary state for the deployed files
    audited_refs: list[str] = field(default_factory=list)
    covered_files: list[str] = field(default_factory=list)
    uncovered_files: list[str] = field(default_factory=list)
    method: str = ""                     # how the ref correspondence was established
    certainty: str = UNKNOWN
    justification: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)


# ---- D5: delta engine (deterministic, no LLM) -----------------------------------------------------
# Functional change categories. Each is keyed on an identifiable SYNTACTIC change, never on a name.
PERMISSION_RELAXATION = "PERMISSION_RELAXATION"                      # a caller restriction removed/broadened, >=1 remains
FUNCTION_PERMISSIONLESS = "FUNCTION_PERMISSIONLESS"                  # all caller gates gone (was gated, now open)
VALIDATION_REMOVED_OR_WEAKENED = "VALIDATION_REMOVED_OR_WEAKENED"    # a require/assert/revert guard removed
TOLERANCE_OR_THRESHOLD_CHANGED = "TOLERANCE_OR_THRESHOLD_CHANGED"    # numeric literal / comparison operator changed
ACCOUNTING_OR_ASSET_CONVERSION_CHANGED = "ACCOUNTING_OR_ASSET_CONVERSION_CHANGED"  # arithmetic / conversion stmt changed
DELTA_CATEGORIES = (PERMISSION_RELAXATION, FUNCTION_PERMISSIONLESS, VALIDATION_REMOVED_OR_WEAKENED,
                    TOLERANCE_OR_THRESHOLD_CHANGED, ACCOUNTING_OR_ASSET_CONVERSION_CHANGED)

# Funds proximity (never from a name; only from static elements of the changed function).
DIRECT_USER_FUNDS_PATH = "DIRECT_USER_FUNDS_PATH"       # a value transfer appears in the changed function
INDIRECT_USER_FUNDS_PATH = "INDIRECT_USER_FUNDS_PATH"   # reserved; only when statically established
NO_IDENTIFIED_FUNDS_PATH = "NO_IDENTIFIED_FUNDS_PATH"   # view/pure, no transfer: no funds path
FUNDS_UNKNOWN = "UNKNOWN"
FUNDS_PROXIMITY = (DIRECT_USER_FUNDS_PATH, INDIRECT_USER_FUNDS_PATH, NO_IDENTIFIED_FUNDS_PATH, FUNDS_UNKNOWN)

# Candidate status. STOP conditions force BLOCKED regardless of score.
TC_PRIORITIZED = "PRIORITIZED"            # full evidence chain + a functional delta + plausible funds path
TC_UNCERTAIN = "UNCERTAIN"                # a non-STOP condition missing (coverage/funds unknown): kept, not prioritized
TC_BLOCKED = "BLOCKED"                    # a STOP condition holds
TC_NO_FUNCTIONAL_DELTA = "NO_FUNCTIONAL_DELTA"   # normalized bodies equal: cosmetic / comment / formatting / reorder
TC_STATUSES = (TC_PRIORITIZED, TC_UNCERTAIN, TC_BLOCKED, TC_NO_FUNCTIONAL_DELTA)


@dataclass
class FunctionDelta:
    function: str                        # signature "name(params)"
    change: str                          # added | removed | changed | unchanged
    categories: list[str] = field(default_factory=list)
    funds: str = FUNDS_UNKNOWN
    evidence: list[str] = field(default_factory=list)   # concrete syntactic observations (provenance)


@dataclass
class RankBreakdown:
    delta_priority: float = 0.0          # from the categories present
    fact_certainty: float = 0.0          # from the D1-D4 evidence chain
    audit_coverage: float = 0.0          # higher when the delta is NOT already covered
    funds_proximity: float = 0.0
    validation_capability: float = 0.0   # static-only reproducibility

    def as_dict(self) -> dict:
        return {"delta_priority": self.delta_priority, "fact_certainty": self.fact_certainty,
                "audit_coverage": self.audit_coverage, "funds_proximity": self.funds_proximity,
                "validation_capability": self.validation_capability}


@dataclass
class TriageCandidate:
    chain_id: int
    address: str
    file: str
    audited_ref: str | None
    deployed_ref: str | None
    status: str                          # TC_STATUSES
    deltas: list[FunctionDelta] = field(default_factory=list)
    stop_reasons: list[str] = field(default_factory=list)
    score: float = 0.0
    rank: RankBreakdown = field(default_factory=RankBreakdown)
    certainty: str = UNKNOWN
    justification: list[str] = field(default_factory=list)
    sources: list[Source] = field(default_factory=list)

    @property
    def categories(self) -> list[str]:
        out: list[str] = []
        for d in self.deltas:
            for c in d.categories:
                if c not in out:
                    out.append(c)
        return out
