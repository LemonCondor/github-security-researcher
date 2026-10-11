"""CLI wiring of the local engines (contracts, web): report only, clean errors, nothing stored."""
import json
import os
import subprocess
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def _cli(tmp_path, *args):
    root = tmp_path / "gsr"
    (root / "config").mkdir(parents=True, exist_ok=True)
    (root / "config" / "targets.yaml").write_text("targets: []\n")
    (root / "config" / "policies.yaml").write_text("")
    env = {**os.environ, "GSR_ROOT": str(root), "GSR_DATA_DIR": str(tmp_path / "data"),
           "GSR_WORKSPACE": str(tmp_path / "ws")}
    return subprocess.run(["github-sec", *args], capture_output=True, text=True, env=env, timeout=120)


def test_contracts_scan_cli(tmp_path):
    out = _cli(tmp_path, "contracts", "scan", str(FIX / "contracts"), "--json")
    assert out.returncode == 0, out.stderr
    r = json.loads(out.stdout)
    assert r["findings"] and {f["status"] for f in r["findings"]} <= {"CANDIDATE", "NEEDS_REVIEW", "OBSERVATION"}
    assert _cli(tmp_path, "contracts", "scan", str(tmp_path / "missing")).returncode == 2


def test_web_analyze_cli(tmp_path):
    out = _cli(tmp_path, "web", "analyze", str(FIX / "web" / "neg"), "--json")
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["findings"] == []
    txt = _cli(tmp_path, "web", "analyze", str(FIX / "web" / "pos"))
    assert txt.returncode == 0 and "network=none" in txt.stdout
    bad = _cli(tmp_path, "web", "analyze", str(tmp_path / "missing"))
    assert bad.returncode == 2 and "no such file" in bad.stderr
