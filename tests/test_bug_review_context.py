"""Bounded review context: large enclosing functions become explicit partial excerpts that keep the evidence,
the declaration, the key identifiers' lines (definitions, guards) and mark every omitted range."""
import pytest

pytest.importorskip("tree_sitter_go")

from github_security.bugs import model as bm
from github_security.bugs import review as rv
from github_security.bugs.go_detectors import detect_go_bugs


def write_big(tmp_path, n_filler=380, guard=True):
    """func Big: split at line 6, an unrelated guard mention far away, index near the end."""
    body = ["package app", "", 'import "strings"', "", "func Big(cfg string) string {",
            '\tparts := strings.SplitN(cfg, "\\n", 2)', "\ttotal := 0"]
    for i in range(n_filler):
        body.append(f"\ttotal += {i}")
        if guard and i == n_filler // 2:
            body.append("\tif len(parts) > 5 { total-- } // unrelated mention, not a guard of the index")
    body += ["\t_ = total", "\treturn parts[1]", "}", "",
             "func Small(cfg string) string {", '\tkv := strings.SplitN(cfg, "=", 2)', "\treturn kv[1]", "}"]
    (tmp_path / "big.go").write_text("\n".join(body) + "\n")
    return {c.function: c for c in detect_go_bugs(tmp_path)}


def test_short_function_is_shown_whole(tmp_path):
    c = write_big(tmp_path)["Small"]
    (s,) = rv.build_snippets(tmp_path, c)
    assert not s["partial"] and s["lines"] == list(range(s["start"], s["end"] + 1))
    assert "omitted" not in s["text"] and 'partial="true"' not in rv.build_prompt(c, [s])


def test_large_function_becomes_marked_excerpt_with_evidence(tmp_path):
    c = write_big(tmp_path)["Big"]
    assert c.category == "unchecked-split-index" and c.status == bm.BUG_CANDIDATE
    (s,) = rv.build_snippets(tmp_path, c)
    total = s["end"] - s["start"] + 1
    assert total > rv.FULL_MAX_LINES and s["partial"] and len(s["lines"]) < total / 2
    for ln in c.related_lines + [s["start"], s["end"]]:          # evidence, declaration, closing brace
        assert ln in s["lines"] and f"{ln:>5} |" in s["text"]
    guard = next(i for i, t in enumerate((tmp_path / "big.go").read_text().splitlines(), 1) if "len(parts)" in t)
    assert guard in s["lines"]                                   # far-away mention of `parts` kept (counter-evidence)
    assert "omitted:" in s["text"] and "lines not shown]" in s["text"]
    p = rv.build_prompt(c, [s])
    assert f'partial="true" shown="{len(s["lines"])}/{total}"' in p and "NOT the whole" in p
    full = rv.build_prompt(c, rv.build_snippets(tmp_path, c, full=True))
    assert len(p) < len(full) / 3 and "omitted" not in full


def test_candidate_near_start_and_near_end(tmp_path):
    c = write_big(tmp_path)["Big"]
    (s,) = rv.build_snippets(tmp_path, c)
    assert min(s["lines"]) == s["start"] and max(s["lines"]) == s["end"]       # windows clipped to the function
    near_start = bm.BugCandidate(file="big.go", line=c.related_lines[0], category=c.category, rule=c.rule,
                                 function="Big", explanation="e", suspicion="s", snippet=c.snippet,
                                 confidence=0.6, related_lines=[c.related_lines[0]], context=c.context)
    (s2,) = rv.build_snippets(tmp_path, near_start)
    assert set(range(s2["start"], c.related_lines[0] + rv.WINDOW + 1)) <= set(s2["lines"])


def test_large_callee_keeps_signature_and_every_return(tmp_path):
    lines = ["package app", "", 'import "errors"', "", "func save(p string) error {"]
    for i in range(200):
        lines += [f"\tif p == \"x{i}\" {{", "\t\treturn errors.New(\"bad\")", "\t}"] if i % 50 == 0 else [f"\t_ = {i}"]
    lines += ["\treturn nil", "}", "", "func Use(p string) {", "\tsave(p)", "}"]
    (tmp_path / "c.go").write_text("\n".join(lines) + "\n")
    c = next(x for x in detect_go_bugs(tmp_path) if x.function == "Use")
    callee = next(s for s in rv.build_snippets(tmp_path, c) if s["kind"] == "callee")
    src = (tmp_path / "c.go").read_text().splitlines()
    rets = [i for i, t in enumerate(src, 1) if "return" in t and callee["start"] <= i <= callee["end"]]
    assert callee["partial"] and set(rets) <= set(callee["lines"]) and callee["start"] in callee["lines"]


def test_citations_of_omitted_lines_are_dropped(tmp_path):
    c = write_big(tmp_path)["Big"]
    snips = rv.build_snippets(tmp_path, c)
    omitted = next(n for n in range(snips[0]["start"], snips[0]["end"]) if n not in snips[0]["lines"])
    out, warn = rv.sanitize({"verdict": "LIKELY_BUG", "lines": [{"file": "big.go", "line": omitted}]}, snips)
    assert out["verdict"] == bm.NEEDS_REVIEW and out["lines"] == [] and warn
    shown = c.related_lines[-1]
    out, _ = rv.sanitize({"verdict": "LIKELY_BUG", "lines": [{"file": "big.go", "line": shown}]}, snips)
    assert out["verdict"] == bm.LIKELY_BUG


def test_model_can_ask_for_more_context(tmp_path):
    c = write_big(tmp_path)["Big"]
    snips = rv.build_snippets(tmp_path, c)
    ask = {"verdict": "LIKELY_BUG", "lines": [{"file": "big.go", "line": c.related_lines[-1]}],
           "context_needed": "lines 100-200"}
    out, _ = rv.sanitize(ask, snips)
    assert out["verdict"] == bm.NEEDS_REVIEW and out["context_needed"] == "lines 100-200"
    assert "context_needed" in rv.OUTPUT_SCHEMA["required"]
    seen = {}

    def runner(system, prompt, schema, model=None):
        seen["p"] = prompt
        return {"verdict": "NEEDS_REVIEW", "lines": []}
    rec = rv.review_candidate(tmp_path, c, runner=runner, full_context=True)
    assert "omitted" not in seen["p"] and rec["context_partial"] is False
    rec = rv.review_candidate(tmp_path, c, runner=runner)
    assert rec["context_partial"] is True and rec["prompt_chars"] == len(seen["p"]) + len(rv.SYSTEM_PROMPT)


def test_data_path_of_split_input_is_followed(tmp_path):
    """git-sync shape: kv := SplitN(it) <- range items <- Split(out) <- out := fetch(), far apart."""
    body = ["package app", "", 'import "strings"', "", "func fetch() string { return \"\" }", "",
            "func Chain() string {", "\tn := 0"]
    body += [f"\tn += {i}" for i in range(60)] + ["\tout := fetch() // data source"]
    body += [f"\tn += {i}" for i in range(140)]
    body += ['\titems := strings.Split(out, ",")', "\tfor _, it := range items {",
             '\t\tkv := strings.SplitN(it, "=", 2)', "\t\treturn kv[1]", "\t}", "\treturn \"\"", "}"]
    (tmp_path / "chain.go").write_text("\n".join(body) + "\n")
    c = next(x for x in detect_go_bugs(tmp_path) if x.function == "Chain" and "kv[1]" in x.suspicion)
    (s,) = rv.build_snippets(tmp_path, c)
    src = (tmp_path / "chain.go").read_text().splitlines()
    source_line = next(i for i, t in enumerate(src, 1) if "out := fetch()" in t)
    assert s["partial"] and source_line in s["lines"] and "data source" in s["text"]
