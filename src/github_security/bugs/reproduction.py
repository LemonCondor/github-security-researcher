"""Interfaces for the future reproduction / patch / PR loop. Planning only: NOTHING here executes code.

BugCandidate --plan_reproduction--> ReproductionTask (what a regression test must show)
stored lifecycle states --pr_gate--> list of unmet conditions (empty = may be proposed for a PR)

Execution of third-party code (running a test) will be a separate, explicitly permitted component; a
ReproductionTask is the contract it will receive, so what the agent may run stays reviewable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .model import BUG_CANDIDATE, LIKELY_BUG, BugCandidate

PLANNABLE = (BUG_CANDIDATE, LIKELY_BUG)


@dataclass(frozen=True)
class ReproductionTask:
    bug_fingerprint: str
    category: str
    hypothesis: str
    file: str
    function: str
    lines: tuple[int, ...]
    preconditions: tuple[str, ...]
    trigger: str                    # what the test does
    expected_behavior: str          # correct behaviour (what the test asserts)
    observed_behavior_expected: str # what the buggy code is predicted to do (test must fail before the patch)
    test_kind: str
    executable: bool = False        # never True here: running requires a separate permitted runner
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return asdict(self)


def _callee(c: BugCandidate) -> str:
    return next((x for x in c.context if x["kind"] == "callee"), {}).get("file", "?")


def plan_reproduction(c: BugCandidate) -> ReproductionTask | None:
    """Deterministic plan for a candidate without negative evidence or ambiguity; None otherwise (a suspicion
    that the detector itself could not separate from intent is not worth a reproduction)."""
    if c.status not in PLANNABLE:
        return None
    common = dict(bug_fingerprint=c.fingerprint, category=c.category, file=c.file, function=c.function,
                  lines=tuple(c.related_lines), test_kind="go-unit-test (package-local, injected failure)")
    if c.category == "ignored-error":
        return ReproductionTask(
            hypothesis=c.suspicion,
            preconditions=("the called function can be made to return a non-nil error from a test "
                           "(input, fake dependency or test double) without modifying production code",
                           f"callee declared in {_callee(c)}"),
            trigger=f"call {c.function} with inputs that make the callee fail",
            expected_behavior=f"{c.function} reports the failure (returns / logs / propagates the error)",
            observed_behavior_expected=f"{c.function} completes as if the callee had succeeded",
            notes=("if the callee cannot fail for reachable inputs, mark NOT_REPRODUCED (no patch)",
                   "if the function cannot return an error, the fix may change its signature: human review"),
            **common)
    if c.category == "overwritten-error":
        return ReproductionTask(
            hypothesis=c.suspicion,
            preconditions=("the first call can be made to fail while the second succeeds",),
            trigger=f"call {c.function} so that only the first error-producing call fails",
            expected_behavior=f"{c.function} returns (or handles) the first error",
            observed_behavior_expected=f"{c.function} returns nil / the second result: the first error is lost",
            notes=("minimal fix is usually an `if err != nil { return .. }` between the two calls",),
            **common)
    if c.category == "unchecked-split-index":
        return ReproductionTask(
            hypothesis=c.suspicion,
            preconditions=(f"{c.function} (or an exported caller) can receive the split input from a test",),
            trigger=f"call {c.function} with an input containing fewer separators than the index requires "
                    "(e.g. empty string or no separator)",
            expected_behavior=f"{c.function} returns an error / zero value or skips the input",
            observed_behavior_expected="runtime panic: index out of range",
            notes=("minimal fix: a `len(x) < N` guard (or strings.Cut) with the project's existing error style",
                   "if every caller already guarantees the separator, mark NOT_REPRODUCED (no patch)"),
            **common)
    if c.category == "nil-before-err-check":
        return ReproductionTask(
            hypothesis=c.suspicion,
            preconditions=("the callee can be made to return (nil, non-nil error) from a test",),
            trigger=f"call {c.function} with an input for which the callee fails",
            expected_behavior=f"{c.function} reports / returns the callee error",
            observed_behavior_expected="the nil check exits first: no error reported, the item is silently skipped",
            notes=("minimal fix: examine err before the nil check (as other branches usually do)",),
            **common)
    if c.category == "unchecked-submatch-index":
        return ReproductionTask(
            hypothesis=c.suspicion,
            preconditions=(f"{c.function} (or an exported caller) can receive the matched input from a test",),
            trigger=f"call {c.function} with an input the regular expression does not match",
            expected_behavior=f"{c.function} returns an error / zero value or skips the input",
            observed_behavior_expected="runtime panic: index out of range (FindStringSubmatch returned nil)",
            notes=("minimal fix: an `if m == nil` (or len(m) <= K) check with the project's existing error style",
                   "if every caller already guarantees a match, mark NOT_REPRODUCED (no patch)"),
            **common)
    return None


# Conditions for an automatic PR (future step). Each is a stored fact; none can be asserted by the LLM alone.
PR_GATE = (
    ("status", "bug status is LIKELY_BUG", lambda r: r["status"] == LIKELY_BUG),
    ("validation", "bug validated", lambda r: r["validation_state"] == "VALIDATED"),
    ("reproduction", "reproduced by a regression test", lambda r: r["reproduction_state"] == "REPRODUCED"),
    ("test", "test fails before and passes after the patch",
     lambda r: r["regression_test_state"] == "PASSES_AFTER_PATCH"),
    ("patch", "patch verified (minimal diff, relevant suite green, no unrelated file, conventions, patch review)",
     lambda r: r["patch_state"] == "VERIFIED"),
    ("not_proposed", "no PR proposed / refused / merged before", lambda r: r["pr_state"] == "NONE"),
    ("open", "pattern still present at the scanned commit", lambda r: r["state"] == "open"),
)


def pr_gate(row, settings=None, target=None) -> list[str]:
    """Unmet conditions for proposing a PR for this stored bug (empty list = gate passed).
    Repository policy is checked with the existing security.policy gate (global + per-target switches)."""
    missing = [desc for _, desc, ok in PR_GATE if not ok(row)]
    if settings is not None and target is not None:
        from ..security.policy import PolicyViolation, check_pr_allowed
        try:
            check_pr_allowed(settings, target, 1.0)
        except PolicyViolation as e:
            missing.append(f"policy: {e}")
    else:
        missing.append("policy: repository contribution policy not checked")
    return missing
