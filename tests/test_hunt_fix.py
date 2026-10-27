import subprocess
import sys

from github_security.hunt.fix import commit_branch, verify_fix
from github_security.hunt.lang import Toolchain


def git(r, *a):
    return subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True,
                          capture_output=True, text=True).stdout


def setup(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "m.py").write_text("def f(x):\n    return x + 2\n")
    git(r, "init", "-q"); git(r, "add", "-A"); git(r, "commit", "-qm", "i")
    (r / "m.py").write_text("def f(x):\n    return x + 1\n")
    (r / "test_m.py").write_text("from m import f\n\ndef test_f():\n    assert f(1) == 2\n")
    return r


def test_red_then_green_required(tmp_path):
    r = setup(tmp_path)
    ok, why = verify_fix(r, ["test_m.py"], "py", Toolchain(python=sys.executable))
    assert ok, why
    assert (r / "m.py").read_text().endswith("x + 1\n")  # fix restored after the red run


def test_test_passing_without_fix_is_rejected(tmp_path):
    r = setup(tmp_path)
    (r / "test_m.py").write_text("def test_f():\n    assert True\n")
    assert verify_fix(r, ["test_m.py"], "py", Toolchain(python=sys.executable)) == (False, "new test passes without the fix")


def test_no_tests_or_no_source_change(tmp_path):
    r = setup(tmp_path)
    assert verify_fix(r, [], "py", Toolchain(python=sys.executable))[0] is False
    git(r, "checkout", "--", "m.py")
    assert verify_fix(r, ["test_m.py"], "py", Toolchain(python=sys.executable))[0] is False


def test_commit_branch_excludes_repro(tmp_path):
    r = setup(tmp_path)
    (r / "repro").mkdir()
    (r / "repro/gsr_repro.py").write_text("x")
    sha = commit_branch(r, "fix/gsr-f", "Fix f", "LemonCondor <yomgui12@outlook.com>")
    files = git(r, "show", "--name-only", "--format=%an", sha).split()
    assert files[0] == "LemonCondor" and "repro/gsr_repro.py" not in files and "m.py" in files


def test_commit_branch_excludes_pycache(tmp_path):
    r = setup(tmp_path)
    (r / "__pycache__").mkdir()
    (r / "__pycache__/m.cpython-313.pyc").write_bytes(b"x")
    sha = commit_branch(r, "fix/gsr-f", "Fix f", "LemonCondor <yomgui12@outlook.com>")
    files = git(r, "show", "--name-only", "--format=%an", sha).split()
    assert "__pycache__/m.cpython-313.pyc" not in files and "m.py" in files
