"""Trusted configuration (local files only). Repository content never reaches here."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
DISCLOSURE_MODES = {"report_only", "private_advisory", "pull_request"}


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    owner: str
    repository: str
    branch: str | None = None
    commit: str | None = None          # pinned 40-hex SHA: the clone is checked out exactly there (or refused)
    policy_reference: str | None = None
    disclosure: str = "report_only"
    allow_pull_requests: bool = False

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repository}".lower()


@dataclass(frozen=True)
class Policies:
    allow_pr_creation: bool = False
    allow_issue_creation: bool = False
    allow_comment_creation: bool = False
    pr_confidence_threshold: float = 0.85
    max_repo_size_mb: int = 500
    clone_depth: int = 50
    scanners_enabled: tuple[str, ...] = ("semgrep", "gitleaks", "osv", "go_dataflow")
    semgrep_registry_packs: tuple[str, ...] = ()
    llm_model: str | None = None


@dataclass
class Settings:
    root: Path
    targets: list[Target] = field(default_factory=list)
    blocked: set[str] = field(default_factory=set)
    policies: Policies = field(default_factory=Policies)

    @property
    def data_dir(self) -> Path:
        return Path(os.environ.get("GSR_DATA_DIR", self.root / "data"))

    @property
    def workspace(self) -> Path:
        return Path(os.environ.get("GSR_WORKSPACE", self.root / "workspace"))

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"


def _validate_name(value, what: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value) or ".." in value:
        raise ConfigError(f"invalid {what}: {value!r}")
    return value


def _validate_pack(p) -> str:
    if not isinstance(p, str) or not re.fullmatch(r"(p|r)/[A-Za-z0-9._-]+", p):
        raise ConfigError(f"invalid semgrep registry pack {p!r} (expected p/<name> or r/<id>)")
    return p


def parse_target(raw: dict) -> Target:
    if not isinstance(raw, dict):
        raise ConfigError(f"target must be a mapping, got {raw!r}")
    disclosure = raw.get("disclosure", "report_only")
    if disclosure not in DISCLOSURE_MODES:
        raise ConfigError(f"invalid disclosure {disclosure!r}")
    ref = raw.get("policy_reference")
    if ref is not None and not str(ref).startswith("https://"):
        raise ConfigError(f"policy_reference must be an https URL: {ref!r}")
    branch = raw.get("branch")
    if branch is not None and (not re.match(r"^[A-Za-z0-9._/-]{1,200}$", branch) or ".." in branch
                               or branch.startswith("-")):
        raise ConfigError(f"invalid branch {branch!r}")
    commit = raw.get("commit")
    if commit is not None and not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
        raise ConfigError(f"invalid commit {commit!r} (expected a full 40-hex SHA)")
    return Target(
        owner=_validate_name(raw.get("owner"), "owner"),
        repository=_validate_name(raw.get("repository"), "repository"),
        branch=branch,
        commit=commit,
        policy_reference=ref,
        disclosure=disclosure,
        allow_pull_requests=raw.get("allow_pull_requests") is True,
    )


def load(root: Path | None = None) -> Settings:
    root = Path(root or os.environ.get("GSR_ROOT") or Path(__file__).resolve().parents[2])
    tpath, ppath = root / "config" / "targets.yaml", root / "config" / "policies.yaml"
    tdata = yaml.safe_load(tpath.read_text()) if tpath.exists() else {}
    pdata = yaml.safe_load(ppath.read_text()) if ppath.exists() else {}
    tdata, pdata = tdata or {}, pdata or {}

    targets = [parse_target(t) for t in (tdata.get("targets") or [])]
    blocked = {str(b).lower() for b in (tdata.get("blocked_targets") or [])}
    clone = pdata.get("clone") or {}
    policies = Policies(
        allow_pr_creation=pdata.get("allow_pr_creation") is True,
        allow_issue_creation=pdata.get("allow_issue_creation") is True,
        allow_comment_creation=pdata.get("allow_comment_creation") is True,
        pr_confidence_threshold=float(pdata.get("pr_confidence_threshold", 0.85)),
        max_repo_size_mb=int(clone.get("max_repo_size_mb", 500)),
        clone_depth=int(clone.get("depth", 50)),
        scanners_enabled=tuple((pdata.get("scanners") or {}).get("enabled") or Policies.scanners_enabled),
        llm_model=(pdata.get("llm") or {}).get("model"),
        semgrep_registry_packs=tuple(_validate_pack(p) for p in
                                     (pdata.get("scanners") or {}).get("semgrep_registry_packs") or []),
    )
    return Settings(root=root, targets=targets, blocked=blocked, policies=policies)
