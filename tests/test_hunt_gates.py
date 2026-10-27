from github_security.hunt.gates import check_gates


def fake(outputs):
    return lambda script, slug: outputs[script]


def test_stop_and_ecarte_block():
    ok, why = check_gates("a/b", fake({"gates.py": "a/b STOP\n    AUTOCLOSE 8/8\n",
                                       "responsiveness.py": "a/b A python"}))
    assert not ok and "STOP" in why
    ok, why = check_gates("a/b", fake({"gates.py": "a/b GO\n", "responsiveness.py": "a/b ECARTE x"}))
    assert not ok and "ECARTE" in why


def test_go_and_caution_pass():
    ok, why = check_gates("a/b", fake({"gates.py": "a/b CAUTION\n    CLA cla\n", "responsiveness.py": "a/b B go"}))
    assert ok and "CAUTION" in why
