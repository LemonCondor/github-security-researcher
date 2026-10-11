import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from github_security import config as cfg
from github_security.security.policy import (PolicyViolation, check_pr_allowed,
                                              resolve_target)
from github_security.security.secrets import REDACTED, redact, redact_obj


def write_cfg(root: Path, targets: str, policies: str = "") -> cfg.Settings:
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "targets.yaml").write_text(targets)
    (root / "config" / "policies.yaml").write_text(policies)
    return cfg.load(root)


# --- redaction -------------------------------------------------------------

@pytest.mark.parametrize("secret", [
    "ghp_" + "a1B2" * 9,
    "github_pat_" + "x" * 40,
    "sk-ant-api03-" + "Z" * 30,
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "gsk_" + "q" * 30,
])
def test_redacts_known_tokens(secret):
    out = redact(f"value={secret} tail")
    assert secret not in out and REDACTED in out


def test_redacts_kv_header_and_url_creds():
    assert "hunter22" not in redact("password = hunter22")
    assert "abc.def" not in redact("Authorization: Bearer abc.def")
    assert "s3cr3t" not in redact("https://user:s3cr3t@github.com/x.git")
    assert redact_obj({"a": ["token=abcdefgh"]})["a"][0].endswith(REDACTED)


def test_plain_text_untouched():
    assert redact("nothing secret here") == "nothing secret here"


# --- config / scope --------------------------------------------------------

def test_default_scope_is_empty_and_prs_off(tmp_path):
    s = write_cfg(tmp_path, "targets: []\n")
    assert s.targets == []
    assert s.policies.allow_pr_creation is False
    with pytest.raises(PolicyViolation):
        resolve_target(s, "octocat/Hello-World")


def test_blocked_wins_over_allowed(tmp_path):
    s = write_cfg(tmp_path, "targets:\n- {owner: a, repository: b}\nblocked_targets: [A/B]\n")
    with pytest.raises(PolicyViolation, match="blocked"):
        resolve_target(s, "a/b")


@pytest.mark.parametrize("bad", [
    "- {owner: '../etc', repository: b}",
    "- {owner: a, repository: 'b;rm'}",
    "- {owner: a, repository: b, branch: '--upload-pack=x'}",
    "- {owner: a, repository: b, policy_reference: 'http://insecure'}",
    "- {owner: a, repository: b, disclosure: yolo}",
])
def test_invalid_targets_rejected(tmp_path, bad):
    with pytest.raises(cfg.ConfigError):
        write_cfg(tmp_path, f"targets:\n{bad}\n")


def test_truthy_strings_do_not_enable_prs(tmp_path):
    s = write_cfg(tmp_path,
                  "targets:\n- {owner: a, repository: b, allow_pull_requests: 'yes', disclosure: pull_request}\n",
                  "allow_pr_creation: 'true'\n")
    t = resolve_target(s, "a/b")
    assert t.allow_pull_requests is False and s.policies.allow_pr_creation is False


def test_pr_gate_requires_all_conditions(tmp_path):
    s = write_cfg(tmp_path,
                  "targets:\n- {owner: a, repository: b, allow_pull_requests: true, disclosure: pull_request}\n"
                  "- {owner: a, repository: c, allow_pull_requests: true}\n",
                  "allow_pr_creation: true\npr_confidence_threshold: 0.9\n")
    check_pr_allowed(s, resolve_target(s, "a/b"), 0.95)
    with pytest.raises(PolicyViolation, match="threshold"):
        check_pr_allowed(s, resolve_target(s, "a/b"), 0.5)
    with pytest.raises(PolicyViolation, match="not enabled"):  # disclosure != pull_request
        check_pr_allowed(s, resolve_target(s, "a/c"), 0.99)


# --- CLI / clone (network) -------------------------------------------------

needs_net = pytest.mark.skipif(
    not shutil.which("gh") or os.environ.get("GSR_OFFLINE") == "1", reason="needs gh + network")


def run_cli(root: Path, *args):
    env = {**os.environ, "GSR_ROOT": str(root)}
    return subprocess.run(["github-sec", *args], capture_output=True, text=True, env=env, timeout=300)


def test_cli_refuses_out_of_scope_clone(tmp_path):
    write_cfg(tmp_path, "targets: []\n")
    r = run_cli(tmp_path, "clone", "octocat/Hello-World")
    assert r.returncode == 3 and "explicit scope" in r.stderr
    assert not (tmp_path / "workspace").exists()


@needs_net
def test_clone_in_scope_public_repo_is_hardened(tmp_path):
    write_cfg(tmp_path, "targets:\n- {owner: octocat, repository: Hello-World}\n")
    r = run_cli(tmp_path, "clone", "octocat/Hello-World")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert len(out["commit"]) == 40
    repo = Path(out["path"])
    assert (repo / "README").exists()
    # second run = update path, same commit
    r2 = run_cli(tmp_path, "clone", "octocat/Hello-World")
    assert r2.returncode == 0 and json.loads(r2.stdout)["commit"] == out["commit"]
    # no credentials persisted in the clone's config
    gitcfg = (repo / ".git" / "config").read_text()
    assert "@" not in gitcfg.split("url =")[1].splitlines()[0]
    # structured log written, no token-looking strings
    log = (tmp_path / "data" / "logs" / "events.jsonl").read_text()
    assert "clone_or_update.done" in log and "ghp_" not in log and "gho_" not in log


def test_target_commit_pin_is_validated():
    from github_security.config import ConfigError, parse_target
    sha = "f18d1137c63a26e85b91ce639e7bc72bb9a82736"
    assert parse_target({"owner": "o", "repository": "r", "commit": sha}).commit == sha
    assert parse_target({"owner": "o", "repository": "r"}).commit is None
    for bad in ("f18d113", "main", "--upload-pack=x", sha.upper(), sha + "0"):
        with pytest.raises(ConfigError):
            parse_target({"owner": "o", "repository": "r", "commit": bad})
