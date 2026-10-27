import json
import sys
from pathlib import Path

import pytest

from github_security.hunt.lang import Toolchain, detect_lang, repro_cmd, run, test_cmd
from github_security.hunt.model import Finding, Result


def test_detect_lang(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    assert detect_lang(tmp_path) == "go"
    (tmp_path / "go.mod").unlink()
    (tmp_path / "package.json").write_text("{}")
    assert detect_lang(tmp_path) == "js"
    (tmp_path / "package.json").unlink()
    (tmp_path / "pyproject.toml").write_text("")
    assert detect_lang(tmp_path) == "py"
    (tmp_path / "pyproject.toml").unlink()
    with pytest.raises(ValueError):
        detect_lang(tmp_path)


def test_commands(tmp_path):
    tc = Toolchain(python="/v/bin/python", go="/g/go", node="node")
    assert repro_cmd("py", "repro/r.py", tc) == ["/v/bin/python", "repro/r.py"]
    assert repro_cmd("go", "pkg/a/gsr_repro_test.go", tc) == ["/g/go", "test", "-count=1", "-run", "TestGsrRepro",
                                                              "./pkg/a"]
    assert repro_cmd("js", "repro/r.mjs", tc) == ["node", "repro/r.mjs"]
    assert test_cmd("py", "tests/t.py", tmp_path, tc)[:3] == ["/v/bin/python", "-m", "pytest"]
    assert test_cmd("js", "a.test.js", tmp_path, tc) == ["node", "--test", "a.test.js"]
    (tmp_path / "package.json").write_text(json.dumps({"devDependencies": {"vitest": "1"}}))
    assert test_cmd("js", "a.test.js", tmp_path, tc) == ["npx", "vitest", "run", "a.test.js"]


def test_run_exit_code_and_timeout(tmp_path):
    assert run(["python3", "-c", "import sys; print('x'); sys.exit(3)"], tmp_path)[0] == 3
    assert run(["python3", "-c", "import time; time.sleep(5)"], tmp_path, timeout=1) == (124, "timeout")


def test_result_to_dict():
    f = Finding("a.py", "f", "h", "i", "e", "o", "repro/r.py", "u", 0.5)
    d = Result("READY", target="a.py", finding=f, branch="b").to_dict()
    assert d["finding"]["function"] == "f" and d["status"] == "READY"


def test_run_puts_worktree_src_first_on_pythonpath(tmp_path, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/elsewhere")
    (tmp_path / "src").mkdir()
    code, out = run([sys.executable, "-c", "import os;print(os.environ['PYTHONPATH'])"], tmp_path)
    assert code == 0 and out.strip().split(":") == [str(tmp_path / "src"), str(tmp_path), "/elsewhere"]


def test_detect_lang_mixed_markers_uses_majority(tmp_path):
    import subprocess
    (tmp_path / "pyproject.toml").write_text("")
    (tmp_path / "package.json").write_text("{}")
    for name in ("a.py", "b.py", "c.js"):
        (tmp_path / name).write_text("")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    assert detect_lang(tmp_path) == "py"
