"""Tool-enabled `claude -p` runner for the hunter/fixer roles, restricted to a throwaway worktree.

Built-in tools are limited to Read/Grep/Glob/Edit/Write/Bash; permission rules restrict writes and commands,
network tools and gh/git push are denied, and credentials are stripped from the environment.
Not a kernel sandbox: code run via python/node/go can still reach the network; secrets are hidden from HOME and
env, and only reputable gated repos are hunted."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from ..ai.reviewer import ReviewError, _env
from ..security.secrets import redact
from .lang import Toolchain, py_path_env

TOOLS = "Read,Grep,Glob,Edit,Write,Bash"
DENY = ["WebFetch", "WebSearch", "Bash(gh:*)", "Bash(git push:*)", "Bash(git commit:*)", "Bash(curl:*)",
        "Bash(wget:*)", "Bash(pip:*)", "Bash(npm:*)", "Bash(rm:*)", "Read(//root/**)", "Edit(//root/**)",
        "Write(//root/**)", "Read(//home/**)", "Edit(//home/**)", "Write(//home/**)", "Bash(mv:*)", "Bash(chmod:*)",
        "Bash(git reset:*)", "Bash(git clean:*)", "Bash(git checkout:*)", "Bash(git config:*)"]


@contextmanager
def isolated_home(real_home: Path = Path.home()):
    """Temp HOME holding only the Claude login, so ~/.ssh, ~/.config/gh etc. are not under ~ for the agent."""
    with tempfile.TemporaryDirectory(prefix="gsr-home-") as d:
        home = Path(d)
        (home / ".claude").mkdir()
        cred = real_home / ".claude" / ".credentials.json"
        if cred.is_file():
            shutil.copy2(cred, home / ".claude" / ".credentials.json")
            os.chmod(home / ".claude" / ".credentials.json", 0o600)
        (home / ".claude.json").write_text(json.dumps({"hasCompletedOnboarding": True}))
        yield home


def agent_env(home: Path, cwd: Path | None = None) -> dict:
    env = _env()
    for k in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        env.pop(k, None)
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"))
    if cwd is not None:
        env.update(py_path_env(cwd))
    return env


def _bash(tc: Toolchain) -> list[str]:
    cmds = ["python", "python3", tc.python, "pytest", tc.go + " test", "go test", tc.node, "node", "npx vitest",
            "npx jest", "git diff", "git log", "git status"]
    return [f"Bash({c}:*)" for c in dict.fromkeys(cmds)]


def hunt_allow(tc: Toolchain) -> list[str]:
    return ["Read", "Grep", "Glob", "Write(repro/**)", "Edit(repro/**)", "Write(**/gsr_repro_test.go)",
            "Edit(**/gsr_repro_test.go)", *_bash(tc)]


def fix_allow(tc: Toolchain) -> list[str]:
    return ["Read", "Grep", "Glob", "Edit(./**)", "Write(./**)", *_bash(tc)]


def build_cmd(exe: str, system: str, schema: dict, allow: list[str], deny: list[str], model: str | None) -> list[str]:
    cmd = [exe, "-p", "--tools", TOOLS, "--allowedTools", ",".join(allow), "--disallowedTools", ",".join(deny),
           "--permission-mode", "dontAsk", "--max-budget-usd", "3", "--strict-mcp-config", "--setting-sources", "", "--no-session-persistence", "--disable-slash-commands",
           "--system-prompt", system, "--output-format", "json", "--json-schema", json.dumps(schema)]
    return cmd + (["--model", model] if model else [])


def claude_agent_runner(system: str, prompt: str, schema: dict, *, cwd: Path, allow: list[str],
                        model: str | None = None, timeout: int = 1200) -> dict:
    exe = shutil.which("claude")
    if not exe:
        raise ReviewError("claude CLI not found")
    try:
        with isolated_home() as home:
            proc = subprocess.run(build_cmd(exe, system, schema, allow, DENY, model), input=prompt,
                                  capture_output=True, text=True, timeout=timeout, cwd=cwd, env=agent_env(home, cwd))
    except subprocess.TimeoutExpired as e:
        raise ReviewError(f"claude timed out after {timeout}s") from e
    if proc.returncode != 0:
        raise ReviewError(redact(f"claude exit {proc.returncode}: {(proc.stderr or proc.stdout)[-600:]}"))
    try:
        env = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise ReviewError("claude returned non-JSON output") from e
    out = env.get("structured_output")
    if env.get("is_error") or not isinstance(out, dict):
        raise ReviewError(redact(str(env.get("result"))[:600]))
    return out
