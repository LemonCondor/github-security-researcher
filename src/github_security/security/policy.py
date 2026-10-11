"""Scope + action gates. Every outward-facing action must pass through here."""
from __future__ import annotations

from ..config import Settings, Target


class PolicyViolation(PermissionError):
    pass


def resolve_target(settings: Settings, slug: str) -> Target:
    """Return the configured target for OWNER/REPO, or raise. No implicit scope."""
    slug = slug.strip().lower()
    if slug in settings.blocked:
        raise PolicyViolation(f"{slug} is in blocked_targets")
    for t in settings.targets:
        if t.slug == slug:
            return t
    raise PolicyViolation(f"{slug} is not in config/targets.yaml (explicit scope required)")


def check_pr_allowed(settings: Settings, target: Target, confidence: float) -> None:
    if not settings.policies.allow_pr_creation:
        raise PolicyViolation("global allow_pr_creation is false")
    if not target.allow_pull_requests or target.disclosure != "pull_request":
        raise PolicyViolation(f"{target.slug}: pull requests not enabled for this target")
    if confidence < settings.policies.pr_confidence_threshold:
        raise PolicyViolation(
            f"confidence {confidence:.2f} < threshold {settings.policies.pr_confidence_threshold:.2f}")


def check_issue_allowed(settings: Settings, target: Target) -> None:
    if not settings.policies.allow_issue_creation:
        raise PolicyViolation("global allow_issue_creation is false")


def check_comment_allowed(settings: Settings, target: Target) -> None:
    if not settings.policies.allow_comment_creation:
        raise PolicyViolation("global allow_comment_creation is false")
