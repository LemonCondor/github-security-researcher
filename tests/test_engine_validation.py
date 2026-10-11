"""Guards of the independent validation protocol (tests/fixtures/validation/). Deliberately NO metric threshold:
the corpora measure the engines, they are not targets to tune the rules against."""
import hashlib
import importlib.util
import json
import socket
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_solidity")

ROOT = Path(__file__).resolve().parent.parent
VAL = ROOT / "tests" / "fixtures" / "validation"
spec = importlib.util.spec_from_file_location("validate_engines", ROOT / "scripts" / "validate_engines.py")
ve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ve)


@pytest.mark.parametrize("engine", ["contracts", "web"])
def test_corpus_still_matches_frozen_hashes(engine):
    d = VAL / engine
    for line in (d / "FROZEN.sha256").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest, name
    assert json.loads((d / "labels.json").read_text())["frozen_before_engine_run"] is True


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, boom)


@pytest.mark.parametrize("engine", ["contracts", "web"])
def test_validation_runs_offline_reproducibly_and_never_confirms(engine, no_network):
    res = getattr(ve, engine)()
    assert res["reproducible"] is True
    assert all(x["engine_status"] != "CONFIRMED" for x in res["cases"])
    assert {x["truth"] for x in res["cases"]} <= {"VULN", "SAFE", "AMBIGUOUS", "FACT"}


def test_web_malformed_input_is_an_error_not_a_safe_result(no_network):
    res = ve.web()
    assert res["expected_input_errors_reported"] is True and res["findings_on_malformed_inputs"] == []


def test_web_secret_like_values_never_leak(no_network):
    blob = json.dumps(ve.web(), default=str)
    for raw in ("AKIAQ3EGUSXYZ7J2KD4M", "Zx9Zx9Zx9Zx9", "syntheticsynthetic", "Zq8!synthetic"):
        assert raw not in blob


def test_solidity_corpus_parses_without_errors():
    assert ve.contracts()["parse_errors"] == []
