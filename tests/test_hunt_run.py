import subprocess
import sys

from github_security.hunt.lang import Toolchain
from github_security.hunt.run import HuntOptions, hunt

BODY = "\n".join(f"# parse line {i}" for i in range(40))


def make_repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "pyproject.toml").write_text("")
    (r / "pkg").mkdir()
    (r / "pkg/__init__.py").write_text("")
    (r / "pkg/parser.py").write_text(BODY + "\ndef parse_num(s):\n    return int(s.split('.')[0])\n")
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "i"]):
        subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True)
    return r


FINDING = {"file": "pkg/parser.py", "function": "parse_num", "hypothesis": "dotted names", "realistic_input": "a.b.7",
           "expected": "7", "actual": "ValueError", "repro_path": "repro/gsr_repro.py", "user_impact": "crash",
           "confidence": 0.9}


def fake_agent(system, prompt, schema, *, cwd, allow, model=None, timeout=0):
    if "findings" in schema["properties"]:
        (cwd / "repro").mkdir(exist_ok=True)
        (cwd / "repro/gsr_repro.py").write_text("import sys; sys.path.insert(0, '.')\n"
                                                "from pkg.parser import parse_num\n"
                                                "try:\n    r = parse_num('a.b.7')\nexcept ValueError:\n    r = None\n"
                                                "assert r == 7\n")
        return {"findings": [FINDING]}
    p = cwd / "pkg/parser.py"
    p.write_text(p.read_text().replace("s.split('.')[0]", "s.rsplit('.', 1)[-1]"))
    (cwd / "tests").mkdir(exist_ok=True)
    (cwd / "tests/test_parse.py").write_text("from pkg.parser import parse_num\n\ndef test_dotted():\n"
                                             "    assert parse_num('a.b.7') == 7\n")
    return {"fixed": True, "test_files": ["tests/test_parse.py"], "summary": "use last dot"}


def opts():
    return HuntOptions(files=1, toolchain=Toolchain(python=sys.executable))


def test_planted_bug_becomes_ready_branch(tmp_path):
    repo = make_repo(tmp_path)
    results, report = hunt("a/b", repo, opts(), out_dir=tmp_path / "out", agent=fake_agent,
                           skeptic=lambda *a, **k: {"verdict": "KEEP", "reason": "real"},
                           gate=lambda s: (True, "GO"), dup=lambda s, f: None)
    assert [r.status for r in results] == ["READY"], results
    assert results[0].branch == "fix/gsr-parse-num" and report.exists()
    shown = subprocess.run(["git", "-C", str(repo), "show", "--name-only", "--format=", results[0].branch],
                           capture_output=True, text=True).stdout.split()
    assert sorted(shown) == ["pkg/parser.py", "tests/test_parse.py"]


def test_gate_skeptic_and_duplicate_paths(tmp_path):
    repo = make_repo(tmp_path)
    res, _ = hunt("a/b", repo, opts(), out_dir=tmp_path / "o1", agent=fake_agent, gate=lambda s: (False, "STOP"))
    assert [r.status for r in res] == ["GATED"]
    res, _ = hunt("a/b", repo, opts(), out_dir=tmp_path / "o2", agent=fake_agent, gate=lambda s: (True, ""),
                  dup=lambda s, f: "https://x/9")
    assert [(r.status, r.detail) for r in res] == [("DUPLICATE", "https://x/9")]
    res, _ = hunt("a/b", repo, opts(), out_dir=tmp_path / "o3", agent=fake_agent, gate=lambda s: (True, ""),
                  dup=lambda s, f: None, skeptic=lambda *a, **k: {"verdict": "DROP", "reason": "artificial"})
    assert [r.status for r in res] == ["DROPPED_SKEPTIC"]


def test_hunter_crash_is_recorded_and_report_written(tmp_path):
    repo = make_repo(tmp_path)

    def boom(*a, **k):
        raise RuntimeError("kaput")

    res, report = hunt("a/b", repo, opts(), out_dir=tmp_path / "o4", agent=boom, gate=lambda s: (True, ""),
                       dup=lambda s, f: None)
    assert [r.status for r in res] == ["ERROR"] and "RuntimeError" in res[0].detail and report.exists()


def test_no_findings_is_recorded(tmp_path):
    repo = make_repo(tmp_path)
    results, _ = hunt("a/b", repo, opts(), out_dir=tmp_path / "out", agent=lambda *a, **k: {"findings": []},
                      skeptic=lambda *a, **k: {}, gate=lambda s: (True, "GO"), dup=lambda s, f: None)
    assert [(r.status, r.target) for r in results] == [("NO_FINDINGS", "pkg/parser.py")]
