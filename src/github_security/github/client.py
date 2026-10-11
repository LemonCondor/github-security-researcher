"""GitHub API access delegated to the authenticated `gh` CLI.

Our process never reads, stores or forwards the token: `gh` owns it.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from ..security.secrets import redact


class GitHubError(RuntimeError):
    pass


def _gh(*args: str, timeout: int = 60) -> str:
    if not shutil.which("gh"):
        raise GitHubError("gh CLI not installed")
    proc = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise GitHubError(redact(proc.stderr.strip() or f"gh exited {proc.returncode}"))
    return proc.stdout


def api(path: str) -> dict | list:
    if path.startswith(("-", "http")):
        raise GitHubError(f"refusing api path {path!r}")
    return json.loads(_gh("api", "-H", "Accept: application/vnd.github+json", path))


def auth_status() -> dict:
    """Login + token scopes (never the token itself)."""
    proc = subprocess.run(["gh", "auth", "status", "-h", "github.com"],
                          capture_output=True, text=True, timeout=30)
    out = proc.stdout + proc.stderr
    scopes = []
    for line in out.splitlines():
        if "Token scopes:" in line:
            scopes = [s.strip(" '") for s in line.split(":", 1)[1].split(",") if s.strip(" '")]
    if proc.returncode != 0:
        return {"authenticated": False, "scopes": []}
    user = api("user")
    return {"authenticated": True, "login": user["login"], "scopes": scopes}


def repo_metadata(owner: str, repo: str) -> dict:
    d = api(f"repos/{owner}/{repo}")
    return {
        "full_name": d["full_name"],
        "private": d["private"],
        "archived": d["archived"],
        "fork": d["fork"],
        "default_branch": d["default_branch"],
        "size_kb": d["size"],
        "clone_url": d["clone_url"],
        "language": d.get("language"),
        "permissions": d.get("permissions", {}),
    }


def security_policy_url(owner: str, repo: str) -> str | None:
    """Best-effort: SECURITY.md in the standard locations of the repo, then the org .github repo."""
    for o, r in ((owner, repo), (owner, ".github")):
        for path in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            try:
                d = api(f"repos/{o}/{r}/contents/{path}")
            except GitHubError:
                continue
            if isinstance(d, dict) and d.get("html_url"):
                return d["html_url"]
    return None


def private_vulnerability_reporting(owner: str, repo: str) -> bool | None:
    try:
        d = api(f"repos/{owner}/{repo}/private-vulnerability-reporting")
        return bool(d.get("enabled"))
    except GitHubError:
        return None
