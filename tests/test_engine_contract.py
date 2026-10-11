"""Common engine finding contract (contracts / web engines): optional typed location, never CONFIRMED."""
import pytest

from github_security.engines.contract import ENGINE_STATUSES, EngineFinding, Evidence


def _f(**kw):
    base = dict(engine="web.passive/1", target="fixture:a", rule="r", category="headers", severity="info",
                confidence=0.5, description="d")
    return EngineFinding(**{**base, **kw})


def test_web_finding_without_repository_fields_and_stable_id():
    a = _f(location={"url": "https://x.invalid/", "header": "csp"}, evidence=[{"kind": "http-header", "detail": "x"}])
    b = _f(location={"header": "csp", "url": "https://x.invalid/"}, engine="web.passive/2")
    assert a.finding_id == b.finding_id and a.finding_id.startswith("e")    # engine version not in identity
    assert isinstance(a.evidence[0], Evidence) and "repository" not in a.to_dict()


def test_contract_location_is_free_typed_and_ids_differ():
    a = _f(engine="contracts.solidity/1", location={"file": "A.sol", "line": 3, "contract": "A", "function": "f"})
    b = _f(engine="contracts.solidity/1", location={"chain": "local", "address": "0x0", "implementation": "0x1"})
    assert a.finding_id != b.finding_id


@pytest.mark.parametrize("kw", [{"status": "CONFIRMED"}, {"status": "FIXED"}, {"severity": "urgent"},
                                {"validation_method": "llm"}])
def test_invalid_values_refused(kw):
    with pytest.raises(ValueError):
        _f(**kw)


def test_confidence_clamped_and_statuses():
    assert _f(confidence=7).confidence == 1.0
    assert "CONFIRMED" not in ENGINE_STATUSES
