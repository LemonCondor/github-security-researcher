"""LLM-written regression test DRAFTS.

Status is always UNEXECUTED. The tool never runs these files, never imports them and never
uses them as evidence for a verdict. They exist so a human can review, adapt and run them
in an environment they control.
"""
from __future__ import annotations

from pathlib import Path

from ..analysis.context import FindingContext
from ..security.secrets import redact
from .prompts import SYSTEM_PROMPT, build_user_prompt

DRAFT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["language", "file_extension", "code", "what_it_checks", "assumptions"],
    "properties": {
        "language": {"type": "string", "maxLength": 40},
        "file_extension": {"type": "string", "enum": ["py", "go", "js", "ts", "java", "rb", "php", "rs", "txt"]},
        "code": {"type": "string", "maxLength": 12000},
        "what_it_checks": {"type": "string", "maxLength": 1500},
        "assumptions": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
    },
}

DRAFT_INSTRUCTIONS = """
Additional task for this call: write a minimal, self-contained REGRESSION UNIT TEST draft for the
project's own test framework that would fail while the weakness exists and pass once it is fixed.
Constraints: unit-level only, uses only local in-process calls and test doubles, no network access,
no real external services, no destructive operations, no real credentials. It will be reviewed by a
human before anyone runs it. Keep it short."""


def _header(ext: str, finding: dict) -> str:
    c = "#" if ext in ("py", "rb", "txt") else "//"
    lines = [
        "STATUS: UNEXECUTED - LLM-GENERATED DRAFT - NOT EVIDENCE",
        "This file was never run by github-security-researcher and proves nothing by itself.",
        f"Finding {finding.get('id')} ({finding.get('category')}) at {finding.get('file')}:{finding.get('line')}",
        "Review fully before running it yourself in an environment you control.",
    ]
    return "\n".join(f"{c} {l}" for l in lines) + "\n\n"


def write_draft(ctx: FindingContext, finding: dict, out_dir: Path, runner, model: str | None = None) -> tuple[Path, dict]:
    prompt = build_user_prompt(ctx)
    raw = runner(SYSTEM_PROMPT + DRAFT_INSTRUCTIONS, prompt, DRAFT_SCHEMA, model=model)
    ext = raw.get("file_extension") if raw.get("file_extension") in DRAFT_SCHEMA["properties"]["file_extension"]["enum"] else "txt"
    out_dir.mkdir(parents=True, exist_ok=True)
    # Non-runnable name on purpose: test runners won't collect "*.UNEXECUTED_DRAFT.<ext>.txt".
    path = out_dir / f"regression_{finding.get('id')}.UNEXECUTED_DRAFT.{ext}.txt"
    path.write_text(_header(ext, finding) + redact(str(raw.get("code", ""))))
    meta = {"status": "UNEXECUTED", "language": raw.get("language"), "what_it_checks": raw.get("what_it_checks"),
            "assumptions": raw.get("assumptions") or [], "model": raw.get("_model") or model}
    return path, meta
