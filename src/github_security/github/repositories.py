"""Hardened cloning of in-scope public repositories."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config import Settings, Target
from ..observability import timed
from ..security.policy import PolicyViolation
from ..security.secrets import redact
from . import client

# Untrusted repo => no hooks, no symlinks, no submodules, no local/ext transports, no creds.
_SAFE_GIT = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.symlinks=false",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "credential.helper=",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
]


class CloneError(RuntimeError):
    pass


@dataclass
class LocalRepo:
    slug: str
    path: Path
    branch: str
    commit: str


def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GH_", "GITHUB_", "GIT_")) and "TOKEN" not in k.upper()}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_LFS_SKIP_SMUDGE="1")
    return env


def git(*args: str, cwd: Path | None = None, timeout: int = 600) -> str:
    proc = subprocess.run(["git", *_SAFE_GIT, *args], cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=_git_env())
    if proc.returncode != 0:
        raise CloneError(redact(proc.stderr.strip()))
    return proc.stdout.strip()


def repo_dir(settings: Settings, target: Target) -> Path:
    return settings.workspace / "repos" / target.owner.lower() / target.repository.lower()


def clone_or_update(settings: Settings, target: Target) -> LocalRepo:
    meta = client.repo_metadata(target.owner, target.repository)
    if meta["private"]:
        raise PolicyViolation(f"{target.slug} is private; only public repositories are in scope")
    size_mb = meta["size_kb"] / 1024
    if size_mb > settings.policies.max_repo_size_mb:
        raise PolicyViolation(f"{target.slug} is {size_mb:.0f} MB > max_repo_size_mb")
    branch = target.branch or meta["default_branch"]
    url = f"https://github.com/{target.owner}/{target.repository}.git"
    dest = repo_dir(settings, target)

    with timed("clone", "clone_or_update", repository=target.slug, branch=branch):
        if (dest / ".git").is_dir():
            git("fetch", "--no-tags", f"--depth={settings.policies.clone_depth}", "origin",
                f"+refs/heads/{branch}:refs/remotes/origin/{branch}", cwd=dest)
            git("checkout", "-q", "--force", "-B", branch, f"origin/{branch}", cwd=dest)
            git("clean", "-q", "-fdx", cwd=dest)
        else:
            if dest.exists():
                shutil.rmtree(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            git("clone", "-q", "--no-tags", "--single-branch", "--branch", branch,
                f"--depth={settings.policies.clone_depth}", "--", url, str(dest))
        if target.commit:
            # Pinned scope: fetch exactly this commit and check it out detached; never scan anything else.
            git("fetch", "--no-tags", "--depth=1", "origin", target.commit, cwd=dest)
            git("checkout", "-q", "--force", "--detach", target.commit, cwd=dest)
            git("clean", "-q", "-fdx", cwd=dest)
        commit = git("rev-parse", "HEAD", cwd=dest)
        if target.commit and commit != target.commit:
            raise PolicyViolation(f"{target.slug}: checkout is {commit}, expected pinned {target.commit}")
    return LocalRepo(slug=target.slug, path=dest, branch=branch, commit=commit)
