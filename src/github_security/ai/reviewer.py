"""Contextual LLM review through the locally authenticated Claude Code CLI.

    claude -p --tools "" --strict-mcp-config --setting-sources "" --no-session-persistence
           --system-prompt <trusted> --json-schema <schema> --output-format json

No tools, no MCP, no user/project settings or hooks, no session saved, empty working directory.
No ANTHROPIC_API_KEY is read or required: the CLI uses the existing Claude Code login.
The model output is re-validated here; it is advisory and never the sole basis for a decision.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Callable

from ..analysis.context import FindingContext
from ..security.secrets import redact, redact_obj
from .prompts import OUTPUT_SCHEMA, SYSTEM_PROMPT, build_user_prompt

VERDICTS = {"confirmed", "likely", "false_positive", "unknown"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


class ReviewError(RuntimeError):
    pass


@dataclass
class Review:
    output: dict
    model: str | None
    duration_ms: int
    context_sha256: str
    warnings: list[str]


def _env() -> dict:
    drop = ("GH_", "GITHUB_", "ANTHROPIC_API_KEY", "OPENAI", "GROQ")
    return {k: v for k, v in os.environ.items() if not k.startswith(drop) and "TOKEN" not in k.upper()}


def claude_cli_runner(system: str, prompt: str, schema: dict, *, model: str | None = None,
                      timeout: int = 300) -> dict:
    exe = shutil.which("claude")
    if not exe:
        raise ReviewError("claude CLI not found")
    cmd = [exe, "-p", "--tools", "", "--strict-mcp-config", "--setting-sources", "",
           "--no-session-persistence", "--disable-slash-commands", "--system-prompt", system,
           "--output-format", "json", "--json-schema", json.dumps(schema)]
    if model:
        cmd += ["--model", model]
    with tempfile.TemporaryDirectory(prefix="gsr-llm-") as cwd:
        try:
            proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout,
                                  cwd=cwd, env=_env())
        except subprocess.TimeoutExpired as e:
            raise ReviewError(f"claude timed out after {timeout}s") from e
    if proc.returncode != 0:
        raise ReviewError(redact(f"claude exit {proc.returncode}: {(proc.stderr or proc.stdout)[-600:]}"))
    try:
        env = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ReviewError("claude returned non-JSON output") from e
    if env.get("is_error"):
        raise ReviewError(redact(str(env.get("result"))[:600]))
    out = env.get("structured_output")
    if not isinstance(out, dict):
        raise ReviewError("no structured_output in claude response")
    models = list((env.get("modelUsage") or {}).keys())
    out["_model"] = models[0] if models else model
    return out


def sanitize_output(raw: dict, ctx: FindingContext) -> tuple[dict, list[str]]:
    """Never trust the model's JSON: re-check types/enums and that cited lines were actually shown."""
    warnings: list[str] = []
    out = {k: raw.get(k) for k in OUTPUT_SCHEMA["properties"]}
    if out["verdict"] not in VERDICTS:
        warnings.append(f"invalid verdict {out['verdict']!r}")
        out["verdict"] = "unknown"
    try:
        out["confidence"] = max(0.0, min(1.0, float(out["confidence"])))
    except (TypeError, ValueError):
        warnings.append("invalid confidence")
        out["confidence"] = 0.0
    if out["severity"] not in SEVERITIES:
        out["severity"] = None
    visible = ctx.visible_lines()
    good, bad = [], []
    for ev in out.get("evidence") or []:
        try:
            key = (str(ev["file"]), int(ev["line"]))
        except (KeyError, TypeError, ValueError):
            bad.append(ev)
            continue
        (good if key in visible else bad).append({"file": key[0], "line": key[1],
                                                  "explanation": str(ev.get("explanation", ""))[:500]})
    if bad:
        warnings.append(f"{len(bad)} evidence item(s) cite lines not present in context (dropped)")
    out["evidence"] = good
    if out["verdict"] in ("confirmed", "likely") and not good:
        warnings.append("positive verdict without verifiable evidence -> downgraded to unknown")
        out["verdict"], out["confidence"] = "unknown", min(out["confidence"], 0.3)
    if out["severity"] == "critical" and out["verdict"] != "confirmed":
        out["severity"] = "high"
        warnings.append("critical severity without confirmed verdict -> capped to high")
    if raw.get("injection_suspected"):
        out["requires_human_review"] = True
    out["requires_human_review"] = bool(out.get("requires_human_review", True))
    out["injection_suspected"] = bool(out.get("injection_suspected"))
    out["warnings"] = warnings
    return redact_obj(out), warnings


def review(ctx: FindingContext, runner: Callable[..., dict] = claude_cli_runner,
           model: str | None = None) -> Review:
    prompt = build_user_prompt(ctx)
    t0 = time.monotonic()
    raw = runner(SYSTEM_PROMPT, prompt, OUTPUT_SCHEMA, model=model)
    ms = int((time.monotonic() - t0) * 1000)
    out, warnings = sanitize_output(raw, ctx)
    return Review(output=out, model=raw.get("_model") or model, duration_ms=ms,
                  context_sha256=ctx.sha256(), warnings=warnings)
