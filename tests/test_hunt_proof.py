import subprocess

import github_security.hunt.proof as proof_mod

from github_security.hunt.lang import Toolchain
from github_security.hunt.model import Finding
from github_security.hunt.proof import _gh_search, add_worktree, find_duplicate, parse_findings, prove, remove_worktree

GOOD = {"file": "m.py", "function": "f", "hypothesis": "h", "realistic_input": "i", "expected": "e",
        "actual": "a", "repro_path": "repro/gsr_repro.py", "user_impact": "u", "confidence": 0.8}


def repo_with(tmp_path, code):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "m.py").write_text(code)
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "i"]):
        subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True)
    return r


def test_parse_findings_drops_malformed():
    bad_path = dict(GOOD, repro_path="../evil.py")
    missing = {k: v for k, v in GOOD.items() if k != "actual"}
    got = parse_findings({"findings": [GOOD, bad_path, missing, dict(GOOD, confidence="x")]})
    assert [f.repro_path for f in got] == ["repro/gsr_repro.py"]


def test_prove_requires_failing_repro_on_clean_tree(tmp_path):
    repo = repo_with(tmp_path, "def f(x):\n    return x + 1\n")
    hunt = add_worktree(repo, tmp_path / "h")
    (hunt / "repro").mkdir()
    (hunt / "repro/gsr_repro.py").write_text("import sys; sys.path.insert(0, '.')\nfrom m import f\nassert f(1) == 3\n")
    f = Finding(**GOOD)
    ok, out = prove(repo, f, "py", Toolchain(), hunt, tmp_path)
    assert ok and "AssertionError" in out
    (hunt / "repro/gsr_repro.py").write_text("import sys; sys.path.insert(0, '.')\nfrom m import f\nassert f(1) == 2\n")
    assert prove(repo, f, "py", Toolchain(), hunt, tmp_path)[0] is False
    (hunt / "repro/gsr_repro.py").unlink()
    assert prove(repo, f, "py", Toolchain(), hunt, tmp_path) == (False, "repro missing")
    remove_worktree(repo, hunt)
    assert not hunt.exists()


def test_find_duplicate_uses_function_name():
    seen = []
    url = find_duplicate("a/b", Finding(**GOOD), search=lambda q: seen.append(q) or "https://x/1")
    assert url == "https://x/1" and "repo:a/b" in seen[0] and " f " in f" {seen[0]} "


def test_prove_rejects_import_error(tmp_path):
    repo = repo_with(tmp_path, "def f(x):\n    return x + 1\n")
    hunt = add_worktree(repo, tmp_path / "h")
    (hunt / "repro").mkdir()
    (hunt / "repro/gsr_repro.py").write_text("import nonexistent_mod_xyz\n")
    assert prove(repo, Finding(**GOOD), "py", Toolchain(), hunt, tmp_path)[0] is False
    remove_worktree(repo, hunt)


def test_parse_findings_strict_shapes():
    assert parse_findings({"findings": {}}) == []
    assert parse_findings([]) == []
    assert parse_findings({"findings": [dict(GOOD, confidence=True)]}) == []
    assert parse_findings({"findings": [dict(GOOD, confidence=1.5)]}) == []
    assert parse_findings({"findings": [dict(GOOD, repro_path="a\\..\\b.py")]}) == []


def test_find_duplicate_fails_closed():
    assert find_duplicate("a/b", Finding(**GOOD), search=lambda q: "SEARCH_FAILED") == "SEARCH_FAILED"


def test_gh_search_missing_gh(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("gh")
    monkeypatch.setattr(proof_mod.subprocess, "run", boom)
    assert _gh_search("q") == "SEARCH_FAILED"
