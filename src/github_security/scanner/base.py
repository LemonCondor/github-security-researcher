"""Common scanner interface + safe subprocess runner."""
from __future__ import annotations

import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from ..analysis.findings import Finding
from ..security.secrets import redact


@dataclass(frozen=True)
class ScanTarget:
    slug: str          # owner/repo, or local:<name> for local fixtures
    path: Path
    commit: str


class ScannerError(RuntimeError):
    pass


def tool_env() -> dict:
    """Environment for third-party tools: no tokens, no git creds."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GH_", "GITHUB_")) and not any(
               s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "API_KEY"))}
    env["SEMGREP_SEND_METRICS"] = "off"
    return env


def run_tool(cmd: list[str], *, timeout: int, ok_codes=(0,), cwd: Path | None = None) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              env=tool_env(), cwd=cwd)
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"{cmd[0]} timed out after {timeout}s") from e
    if proc.returncode not in ok_codes:
        raise ScannerError(redact(f"{cmd[0]} exit {proc.returncode}: {proc.stderr.strip()[-800:]}"))
    return proc.stdout


def safe_relpath(root: Path, p: str | Path) -> str:
    """Repo-relative path; refuses anything resolving outside the repo."""
    root = root.resolve()
    full = (root / p).resolve() if not Path(p).is_absolute() else Path(p).resolve()
    try:
        return str(full.relative_to(root))
    except ValueError as e:
        raise ScannerError(f"path escapes repository: {p}") from e


def read_line(root: Path, rel: str, line: int, max_len: int = 300) -> str:
    try:
        with (root / rel).open(encoding="utf-8", errors="replace") as fh:
            for i, text in enumerate(fh, 1):
                if i == line:
                    return text.rstrip("\n")[:max_len]
    except OSError:
        pass
    return ""


class Scanner(ABC):
    name: str = "base"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def scan(self, target: ScanTarget) -> list[Finding]: ...

    @staticmethod
    def _which(binary: str) -> bool:
        return shutil.which(binary) is not None
