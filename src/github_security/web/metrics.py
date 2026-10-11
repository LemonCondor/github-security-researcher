"""Per-rule TP/FP/FN of the engine against an annotated fixture corpus (expected.json)."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from . import engine


def evaluate(corpus: str | Path, expected_file: str | Path) -> dict[str, dict[str, int]]:
    """expected.json: {"<fixture path relative to corpus>": ["rule", ...]} — every listed fixture is analysed
    alone; a rule found but not expected is a FP, expected but not found is a FN (counted once per fixture)."""
    corpus = Path(corpus)
    expected = json.loads(Path(expected_file).read_text())
    table: dict[str, dict[str, int]] = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0})
    for rel, rules in expected.items():
        got = {f["rule"] for f in engine.run(corpus / rel)["findings"]}
        exp = set(rules)
        for r in got & exp:
            table[r]["TP"] += 1
        for r in got - exp:
            table[r]["FP"] += 1
        for r in exp - got:
            table[r]["FN"] += 1
    return dict(sorted(table.items()))


def format_table(table: dict[str, dict[str, int]]) -> str:
    rows = [f"{'rule':<42} {'TP':>3} {'FP':>3} {'FN':>3}  precision"]
    for rule, c in table.items():
        p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else float("nan")
        rows.append(f"{rule:<42} {c['TP']:>3} {c['FP']:>3} {c['FN']:>3}  {p:.2f}")
    return "\n".join(rows)
