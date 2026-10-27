import json

from github_security.hunt.agent import DENY, agent_env, build_cmd, fix_allow, hunt_allow, isolated_home
from github_security.hunt.lang import Toolchain
from github_security.hunt.model import Target
from github_security.hunt.model import Finding
from github_security.hunt.prompts import HUNT_SCHEMA, fix_prompt, hunt_prompt


def test_hunt_allow_is_sandboxed():
    allow = hunt_allow(Toolchain(python="/v/bin/python"))
    assert "Bash(/v/bin/python:*)" in allow and "Write(repro/**)" in allow
    assert not any(a in ("Edit", "Write", "Bash") for a in allow)
    assert "Edit(./**)" in fix_allow(Toolchain())
    assert {"WebFetch", "WebSearch", "Bash(gh:*)", "Bash(git push:*)"} <= set(DENY)


def test_build_cmd():
    cmd = build_cmd("claude", "SYS", HUNT_SCHEMA, ["Read"], DENY, None)
    assert cmd[:2] == ["claude", "-p"]
    assert cmd[cmd.index("--allowedTools") + 1] == "Read"
    assert "WebFetch" in cmd[cmd.index("--disallowedTools") + 1]
    assert json.loads(cmd[cmd.index("--json-schema") + 1])["required"] == ["findings"]


def test_hunt_prompt_contains_target_and_families():
    p = hunt_prompt(Target("pkg/parser.py", 1.0, []), "py", run_cmd="py repro/gsr_repro.py")
    assert "pkg/parser.py" in p and "`py repro/gsr_repro.py`" in p and "no pipes" in p and "cache key" in p.lower() and "repro/" in p


def test_isolated_home_has_only_claude_login(tmp_path):
    real = tmp_path / "real"
    (real / ".claude").mkdir(parents=True)
    (real / ".claude/.credentials.json").write_text("{}")
    (real / ".ssh").mkdir()
    (real / ".ssh/id_rsa").write_text("secret")
    with isolated_home(real) as home:
        assert (home / ".claude/.credentials.json").exists()
        assert not (home / ".ssh").exists()
        env = agent_env(home)
        assert env["HOME"] == str(home) and "SSH_AUTH_SOCK" not in env
        assert not any("TOKEN" in k.upper() or k.startswith("GH_") for k in env)


def test_build_cmd_limits_and_root_denied():
    cmd = build_cmd("claude", "S", HUNT_SCHEMA, ["Read"], DENY, None)
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    assert "--max-budget-usd" in cmd
    assert "Read(//root/**)" in DENY and "Bash(cat:*)" not in hunt_allow(Toolchain())


def test_hunt_prompt_states_assertion_contract():
    assert "AssertionError" in hunt_prompt(Target("a.py", 1.0, []), "py", run_cmd="x")
    assert "assert.fail" in hunt_prompt(Target("a.js", 1.0, []), "js", run_cmd="x")


def test_agent_env_sets_worktree_pythonpath(tmp_path):
    (tmp_path / "src").mkdir()
    env = agent_env(tmp_path, tmp_path)
    assert env["PYTHONPATH"].split(":")[:2] == [str(tmp_path / "src"), str(tmp_path)]
    assert fix_prompt(Finding("a", "f", "h", "i", "e", "a", "r", "u", 1.0), "py", test_cmd_hint="py -m pytest -q T")
