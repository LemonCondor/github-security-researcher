"""web.passive/2 — offline passive web engine, tested only on local fixtures (no network)."""
from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from github_security.engines.contract import ENGINE_STATUSES
from github_security.web import ENGINE, capture, jslibs, metrics, render_text, run
from github_security.web.checks import parse_csp, parse_set_cookie

CORPUS = Path(__file__).parent / "fixtures" / "web"
EXPECTED = json.loads((CORPUS / "expected.json").read_text())
POS = sorted(k for k in EXPECTED if k.startswith("pos/"))
NEG = sorted(k for k in EXPECTED if k.startswith("neg/"))


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    class NoSocket(socket.socket):
        def __init__(self, *a, **k):
            boom()

    monkeypatch.setattr(socket, "socket", NoSocket)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)


def rules(path) -> set[str]:
    return {f["rule"] for f in run(path)["findings"]}


def test_corpus_has_positive_and_negative_fixtures():
    assert len(POS) >= 30 and len(NEG) >= 20
    assert all(not EXPECTED[k] for k in NEG)


@pytest.mark.parametrize("rel", POS)
def test_positive_fixture_exact_rules(rel):
    assert rules(CORPUS / rel) == set(EXPECTED[rel])


@pytest.mark.parametrize("rel", NEG)
def test_negative_fixture_zero_findings(rel):
    assert rules(CORPUS / rel) == set()


def test_metrics_table_no_fp_no_fn(capsys):
    table = metrics.evaluate(CORPUS, CORPUS / "expected.json")
    with capsys.disabled():
        print("\n" + metrics.format_table(table))
    assert all(c["FP"] == 0 and c["FN"] == 0 for c in table.values()), table
    every_rule = {r for rs in EXPECTED.values() for r in rs}
    assert set(table) == every_rule


def test_full_run_uses_no_network(no_network):
    res = run(CORPUS)
    assert res["network"] == "none" and res["summary"]["total"] > 0
    with pytest.raises(AssertionError):
        socket.create_connection(("example.test", 80))


def test_package_imports_no_network_module():
    src = Path(capture.__file__).parent
    banned = ("import socket", "import requests", "import httpx", "urllib.request", "http.client", "urlopen",
              "import aiohttp", "subprocess")
    for py in src.glob("*.py"):
        text = py.read_text()
        assert not [b for b in banned if b in text], py.name


def test_contract_statuses_and_limitations():
    res = run(CORPUS)
    json.dumps(res)                                       # serialisable
    for f in res["findings"]:
        assert f["status"] in ENGINE_STATUSES and f["status"] != "CONFIRMED"
        assert f["engine"] == ENGINE
        assert f["limitations"] and f["evidence"] and f["location"].get("url")
        assert f["severity"] in ("info", "low", "medium", "high")
    hdr = [f for f in res["findings"] if f["rule"].startswith("web.hdr.")]
    assert hdr and all(f["status"] == "OBSERVATION" and f["severity"] in ("info", "low") for f in hdr)
    lib = [f for f in res["findings"] if f["rule"] == "web.js.known-vulnerable-library"]
    assert lib and all(f["status"] == "CANDIDATE" and
                       any("reachability/exploitability not shown" in l for l in f["limitations"]) for f in lib)
    redir = [f for f in res["findings"] if f["rule"] == "web.redirect.open-redirect-candidate"]
    assert redir and all(f["status"] == "NEEDS_REVIEW" for f in redir)


def test_secret_values_are_redacted():
    dumped = json.dumps(run(CORPUS))
    for raw in ("AKIAQ3EGTFIXTURE7Z5K", "Fx1turEOnlyNotARealT0kenAbCdEfGhIjKl", "FixtureOnlyNotReal4bCdEfGh",
                "SyFixtureOnly-NotARealKey_abcdefghi", "FIXTUREFIXTUREFIXTURE", "s3cr3tv4lue",
                "fixture-not-real", "redactedvaluefixture"):
        assert raw not in dumped, raw
    assert "redacted" in dumped


def test_https_only_rules_do_not_fire_on_http():
    found = run(CORPUS / "pos" / "redirect_plain_http.http")["findings"]
    assert not [f for f in found if f["rule"] in ("web.hdr.hsts-missing", "web.cookie.secure-missing")]


def test_dedup_counts_occurrences():
    res = run(CORPUS / "pos" / "site_capture.json")
    lib = [f for f in res["findings"] if f["rule"] == "web.js.known-vulnerable-library"]
    assert len(lib) == 1 and lib[0]["extra"]["occurrences"] == 3          # script src + banner + file name
    assert "CVE-2020-11022" in lib[0]["extra"]["advisories"]
    assert "network=none" in render_text(res)


def test_malformed_inputs_are_reported_not_raised(tmp_path):
    (tmp_path / "bad.http").write_text("not an http response\n")
    (tmp_path / "bad.json").write_text('{"format": "web-capture/1", "exchanges": [{"request": {}, "response": {}}]}')
    (tmp_path / "trav.json").write_text(json.dumps({"format": "web-capture/1", "exchanges": [
        {"request": {"url": "https://a.test/"}, "response": {"status": 200, "body_file": "../../etc/passwd"}}]}))
    (tmp_path / "other.json").write_text('{"unrelated": true}')
    res = run(tmp_path)
    assert res["summary"]["total"] == 0 and len(res["inputs"]["errors"]) == 3
    assert any("outside capture directory" in e for e in res["inputs"]["errors"])


def test_raw_parser_meta_and_folding():
    ex = capture.parse_raw_response("# url: https://a.test/x\n# request-header: Origin: https://b.test\n"
                                    "HTTP/1.1 200 OK\r\nX-A: 1\r\n  continued\r\nSet-Cookie: a=1\r\n"
                                    "Set-Cookie: b=2\r\n\r\nbody\n", "t")
    assert ex.url == "https://a.test/x" and ex.request_headers.get("origin") == "https://b.test"
    assert ex.headers.get("x-a") == "1 continued" and ex.headers.get_all("set-cookie") == ["a=1", "b=2"]
    assert ex.body == "body\n"


def test_parsers_and_version_table():
    csp = parse_csp("default-src 'self'; script-src 'self' 'nonce-x'; script-src *")
    assert csp["script-src"] == ["'self'", "'nonce-x'"]                  # first directive wins
    name, val, attrs = parse_set_cookie("__Host-a=b=c; Secure; Path=/; SameSite=Lax")
    assert (name, val, attrs["path"], "secure" in attrs) == ("__Host-a", "b=c", "/", True)
    ids = lambda lib, v: {row[3] for row in jslibs.known_vulns(lib, v)}
    assert ids("jquery", "3.4.1") == {"CVE-2020-11022", "CVE-2020-11023"}
    assert ids("jquery", "3.5.0") == set() and ids("lodash", "4.17.21") == set()
    assert "CVE-2019-8331" in ids("bootstrap", "4.3.0") and ids("bootstrap", "4.3.1") == set()
    assert jslibs.detect_in_url("/vendor/jquery-ui-1.13.2/jquery-ui.min.js") == []


def test_engine_version_bumped():
    assert ENGINE == "web.passive/2"


def test_real_banner_formats_and_versions():
    det = lambda name: jslibs.detect_in_body((CORPUS / name).read_text())
    assert det("pos/js_moment_banner_2_24.js") == [("moment", "2.24.0", det("pos/js_moment_banner_2_24.js")[0][2])]
    assert [d[:2] for d in det("pos/js_jquery_unminified_banner.js")] == [("jquery", "1.11.3")]
    assert [d[:2] for d in det("pos/js_lodash_min_banner.js")] == [("lodash", "4.17.15")]
    assert [d[:2] for d in det("pos/js_bootstrap3_banner.js")] == [("bootstrap", "3.3.7")]
    assert [d[:2] for d in det("pos/js_angular_min_banner.js")] == [("angularjs", "1.6.9")]
    for neg in ("neg/js_moment_timezone.js", "neg/js_moment_locale.js", "neg/js_version_mentions.js"):
        assert det(neg) == [], neg
    ids = lambda lib, v: {row[3] for row in jslibs.known_vulns(lib, v)}
    assert ids("moment", "2.29.1") == {"CVE-2022-24785", "CVE-2022-31129"}
    assert ids("moment", "2.29.3") == {"CVE-2022-31129"} and ids("moment", "2.29.4") == set()


def test_partial_versions_are_ranges_not_exact():
    ids = lambda lib, v: {row[3] for row in jslibs.known_vulns(lib, v)}
    assert ids("lodash", "4.17") == set()                    # 4.17.21 fixes everything in the table
    assert ids("moment", "2.29") == set()
    assert "CVE-2020-11022" in ids("jquery", "3.4")         # every 3.4.x release is affected


def test_cors_reflection_reports_vary():
    f = run(CORPUS / "pos" / "cors_reflected_no_vary.http")["findings"][0]
    assert f["extra"]["vary_origin"] is False and any("Vary: Origin absent" in l for l in f["limitations"])
    f = run(CORPUS / "pos" / "cors_reflected.json")["findings"][0]
    assert f["extra"]["vary_origin"] is True


def test_private_key_variants_and_encrypted_severity():
    keys = [f for f in run(CORPUS / "pos" / "secret_private_key_variants.js")["findings"]]
    assert len(keys) == 2 and {f["severity"] for f in keys} == {"high"}
    enc = run(CORPUS / "pos" / "secret_private_key_encrypted.js")["findings"]
    assert len(enc) == 1 and enc[0]["severity"] == "medium"
    dumped = json.dumps(keys + enc)
    assert "FixtureOnlyNotARealOpenSshKeyMaterial" not in dumped and "FixtureOnlyNotARealEcKey" not in dumped


def test_non_html_skip_is_explicit():
    res = run(CORPUS / "neg" / "json_api.http")
    assert res["findings"] == []
    assert res["not_applicable"] and "application/json" in res["not_applicable"][0]["reason"]
    assert "content-security-policy" in res["not_applicable"][0]["checks"]
    assert "[not applicable]" in render_text(res)
    assert run(CORPUS / "neg" / "hardened.http")["not_applicable"] == []
