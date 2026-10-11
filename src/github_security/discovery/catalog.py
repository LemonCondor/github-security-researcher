"""Organisation catalog: explicitly configured orgs (config/organizations.yaml) + orgs discovered by search.
A configured org may be explored (public metadata only); a discovered org stays `pending` until the user
approves it. Being well known is never a trust signal by itself: the GitHub verified-domain flag is recorded."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import ConfigError, _validate_name

CATEGORIES = ("science_agency", "public_admin", "company", "foundation", "community")


@dataclass(frozen=True)
class OrgSpec:
    login: str
    category: str
    label: str | None = None          # human label, e.g. "DINUM"
    note: str | None = None


def load_catalog(root: Path) -> list[OrgSpec]:
    p = Path(root) / "config" / "organizations.yaml"
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text()) or {}
    out = []
    for raw in data.get("organizations") or []:
        if not isinstance(raw, dict):
            raise ConfigError(f"organization entry must be a mapping: {raw!r}")
        cat = raw.get("category")
        if cat not in CATEGORIES:
            raise ConfigError(f"invalid organization category {cat!r} (expected one of {CATEGORIES})")
        out.append(OrgSpec(_validate_name(raw.get("login"), "organization login"), cat, raw.get("label"),
                           raw.get("note")))
    return out
