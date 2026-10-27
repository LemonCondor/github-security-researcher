import subprocess

from github_security.hunt.targeting import rank_files


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True,
                   capture_output=True)


def test_rank_prefers_risky_churned_source(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tests").mkdir()
    body = "\n".join(f"x{i} = {i}" for i in range(40))
    (tmp_path / "pkg/plain.py").write_text(body)
    (tmp_path / "pkg/parser.py").write_text(body + "\ndef parse_date(s):\n    return s.split('-')  # cache key\n")
    (tmp_path / "tests/test_parser.py").write_text(body + "\nparse cache split\n")
    (tmp_path / "pkg/tiny.py").write_text("parse = 1\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    (tmp_path / "pkg/parser.py").write_text((tmp_path / "pkg/parser.py").read_text() + "# x\n")
    _git(tmp_path, "commit", "-qam", "Fix parse_date offset")
    got = rank_files(tmp_path, "py", n=5)
    paths = [t.path for t in got]
    assert paths[0] == "pkg/parser.py"
    assert "tests/test_parser.py" not in paths and "pkg/tiny.py" not in paths
    assert any("fix-commits" in r for r in got[0].reasons)
