import secrets
import shutil
import string
from pathlib import Path

import pytest
import yaml

from github_security.analysis.findings import Finding
from github_security.scanner.base import ScannerError, ScanTarget, safe_relpath
from github_security.scanner.dependencies import (OSVDependencyScanner, discover,
                                                  parse_package_lock, parse_requirements)
from github_security.scanner.gitleaks import GitleaksScanner
from github_security.scanner.runner import dedupe, run_scan
from github_security.scanner.semgrep import SemgrepScanner

FIXTURE = Path(__file__).parent / "fixtures" / "vulnapp"


@pytest.fixture
def vulnapp(tmp_path) -> Path:
    # Copy outside tests/ (semgrep ignores tests/ dirs) and generate the fake secret
    # at runtime so no secret-looking string is ever committed.
    dst = tmp_path / "vulnapp"
    shutil.copytree(FIXTURE, dst)
    tok = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    (dst / "config.py").write_text(f'# GSR_FAKE_SECRET\nGITHUB_TOKEN = "{tok}"\n')
    return dst


def marker_lines(path: Path, marker: str) -> set[int]:
    return {i for i, l in enumerate(path.read_text().splitlines(), 1) if marker in l}


def mk(**kw) -> Finding:
    base = dict(repository="o/r", commit="c", file="a.py", line=1, rule="r", category="xss",
                severity="medium", confidence=0.5, scanner="t", description="d", evidence="x")
    return Finding(**{**base, **kw})


# --- model / dedupe --------------------------------------------------------

def test_fingerprint_ignores_line_and_commit():
    assert mk(line=1, commit="a").fingerprint == mk(line=99, commit="b").fingerprint
    assert mk(evidence="x").fingerprint != mk(evidence="y").fingerprint


def test_dedupe_keeps_strongest_and_merges_refs():
    a = mk(severity="medium", references=["r1"])
    b = mk(severity="high", references=["r2"])
    out = dedupe([a, b])
    assert len(out) == 1 and out[0].severity == "high" and set(out[0].references) == {"r1", "r2"}


def test_unknown_category_normalised_and_bad_severity_rejected():
    assert mk(category="whatever").category == "other"
    with pytest.raises(ValueError):
        mk(severity="catastrophic")


def test_safe_relpath_refuses_escape(tmp_path):
    with pytest.raises(ScannerError):
        safe_relpath(tmp_path, "../../etc/passwd")


# --- dependency parsing (offline) ------------------------------------------

def test_parse_requirements_pins_only():
    deps = list(parse_requirements("Flask[async]==2.0.0\nrequests>=2\n# x==1\nPyYAML == 6.0\n"))
    assert [(d[1], d[2]) for d in deps] == [("flask", "2.0.0"), ("pyyaml", "6.0")]


def test_parse_package_lock_v3():
    lock = '{"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},' \
           '"node_modules/a/node_modules/@s/b":{"version":"1.0.0"}}}'
    assert {(n, v) for _, n, v, _ in parse_package_lock(lock)} == {("lodash", "4.17.20"), ("@s/b", "1.0.0")}


def test_discover_skips_vendored(tmp_path):
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "requirements.txt").write_text("evil==1.0\n")
    (tmp_path / "requirements-dev.txt").write_text("pytest==7.0.0\n")
    assert [d[2] for d in discover(tmp_path)] == ["pytest"]


def test_osv_scanner_with_fake_api_dedupes_aliases(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.0\n")
    post = lambda url, payload, t: {"results": [{"vulns": [{"id": "PYSEC-1"}, {"id": "GHSA-aaaa"}]}]}
    db = {"GHSA-aaaa": {"id": "GHSA-aaaa", "aliases": ["PYSEC-1", "CVE-2023-1"], "summary": "bad",
                        "database_specific": {"severity": "HIGH"}},
          "PYSEC-1": {"id": "PYSEC-1", "aliases": ["GHSA-aaaa"]}}
    get = lambda url, t: db[url.rsplit("/", 1)[-1]]
    out = OSVDependencyScanner(post=post, get=get).scan(ScanTarget("local:x", tmp_path, "c"))
    assert len(out) == 1 and out[0].rule == "GHSA-aaaa" and out[0].severity == "high"
    assert out[0].evidence == "PyPI:flask==2.0.0"


# --- real scanners on the synthetic repo ----------------------------------

needs_semgrep = pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep missing")
needs_gitleaks = pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks missing")


@needs_semgrep
def test_semgrep_internal_rules_precision_recall(vulnapp):
    findings = SemgrepScanner().scan(ScanTarget("local:vulnapp", vulnapp, "c"))
    truth = yaml.safe_load((vulnapp / "expected.yaml").read_text())
    app = vulnapp / "app.py"
    expected = {(v["category"], ln) for v in truth["vulnerabilities"] if v["file"] == "app.py"
                for ln in marker_lines(app, v["marker"])}
    safe = marker_lines(app, "SAFE")
    got = {(f.category, f.line) for f in dedupe(findings)}

    tp = got & expected
    fp_on_traps = {g for g in got if g[1] in safe}
    assert not fp_on_traps, f"false positives on safe code: {fp_on_traps}"
    assert got <= expected, f"unexpected findings: {got - expected}"
    # auth-bypass is a logic flaw: SAST is not expected to find it (LLM stage, M4).
    sast_expected = {e for e in expected if e[0] != "auth-bypass"}
    assert tp == sast_expected, f"missed: {sast_expected - tp}"


@needs_gitleaks
def test_gitleaks_finds_secret_and_never_stores_it(vulnapp):
    token = (vulnapp / "config.py").read_text().split('"')[1]
    out = GitleaksScanner().scan(ScanTarget("local:vulnapp", vulnapp, "c"))
    secrets_found = [f for f in out if f.file == "config.py"]
    assert len(secrets_found) == 1 and secrets_found[0].category == "secret"
    blob = repr([f.to_dict() for f in out])
    assert token not in blob and token[4:20] not in blob


@needs_semgrep
@needs_gitleaks
def test_runner_skips_unavailable_and_survives_errors(vulnapp):
    class Missing(SemgrepScanner):
        name = "missing"
        def available(self): return False

    class Broken(GitleaksScanner):
        name = "broken"
        def scan(self, t): raise ScannerError("boom")

    res = run_scan(ScanTarget("local:v", vulnapp, "c"), [Missing(), Broken(), GitleaksScanner()])
    assert res.scanners_skipped == {"missing": "not installed", "broken": "boom"}
    assert res.scanners_run == ["gitleaks"] and len(res.findings) == 1
