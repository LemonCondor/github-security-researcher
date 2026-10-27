"""Pre-hunt gates: never hunt a repo that auto-closes external PRs, bans agents or ignores outsiders."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[3] / "workspace" / "tools"


def _run_tool(script: str, slug: str) -> str:
    p = subprocess.run([sys.executable, str(TOOLS / script), slug], capture_output=True, text=True, timeout=600)
    return p.stdout


def check_gates(slug: str, runner=_run_tool) -> tuple[bool, str]:
    gates = runner("gates.py", slug).strip()
    resp = runner("responsiveness.py", slug).strip()
    verdict = gates.split()[1] if len(gates.split()) > 1 else "UNKNOWN"
    cls = resp.split()[1] if len(resp.split()) > 1 else "UNKNOWN"
    detail = f"gates={verdict} responsiveness={cls}\n{gates}"
    return verdict in ("GO", "CAUTION") and cls not in ("ECARTE", "MISSING", "API-ERROR"), detail
