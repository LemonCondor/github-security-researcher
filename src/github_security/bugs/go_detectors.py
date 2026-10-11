"""Deterministic Go detectors for ordinary bug candidates (tree-sitter only: nothing compiled or executed).

Reuses GoDataflow's index and call resolution READ-ONLY (a call is only judged when its callee is uniquely
resolved inside the module, from its declared signature). Unresolved / external / interface calls give no
candidate at all: no claim without a declared signature.

ignored-error      expression statement `f(..)` whose resolved callee declares an `error` result.
                   negative evidence: every return of the callee yields a literal `nil` error.
                   ambiguity: explicit `_ = f(..)`, `defer f(..)`, `go f(..)`, a `Close()` METHOD (teardown;
                   measured on ntfy 2026-10-08: 4/4 such sites were deliberate best-effort shutdown).
overwritten-error  `err` assigned from a call, then assigned again later in the SAME statement list with no
                   occurrence of `err` in between (nor in the overwriting right-hand side).
                   negative evidence: first callee resolved and only returns a nil error.
                   ambiguity: a closure in between captures `err`; the function contains `goto`.
unchecked-split-index  `v[K]` (integer literal K) on the result of strings/bytes Split/SplitN/SplitAfter(N)/Fields
                   (or directly on the call) when K is not below the length the call guarantees and no length
                   guard proves len(v) > K: an input without enough separators panics (index out of range).
                   Guards understood: enclosing `if` / `switch len(v)` / early-exit `if` (return, continue,
                   break, panic, goto) whose condition compares len(v) to an integer literal (`||` allowed in
                   early exits). A guard that does not prove the bound is reported as insufficient.
                   negative evidence: constant input and separator whose split has more than K elements.
                   ambiguity: len(v) compared to a non-constant or in a form not modelled, v redefined, the
                   split input passed to a check before the split (Contains, Count, regexp, custom; a plain
                   `s == ""` does not count), non-constant separator with index 0.
                   Early exits include calls to module helpers that end in os.Exit/panic/log.Fatal.
                   Values written later in an enclosing loop or by a closure void the guards written before them
                   (textual reaching definitions do not see loop back edges nor closure writes).
unchecked-submatch-index  `m[K]` on the result of `re.FindStringSubmatch / FindSubmatch(..)` (nil when the input
                   does not match) with no guard proving m non-nil (`m != nil`, `len(m) > K`, `re.MatchString(x)`
                   on the same regexp and input) or with K above the pattern's group count.
                   ambiguity: receiver not proven to be regexp.MustCompile/Compile of a literal, pattern that
                   matches the empty string, group count unknown, input checked by an unmodelled call, constant
                   input, value written later (loop / closure), unmodelled len form.
"""
from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import go_dataflow as gd
from ..analysis.context import _lines, _numbered
from .model import BugCandidate

TEARDOWN_METHODS = {"Close"}
ERR_NAME = "err"                  # Go convention; other error variables are not judged (precision first)
SNIPPET_RADIUS = 3
_PRIOR = {"ignored-error": 0.5, "overwritten-error": 0.7, "unchecked-split-index": 0.6,
          "unchecked-submatch-index": 0.6, "nil-before-err-check": 0.9}
# Ranking prior for a candidate that matches the shape of a bug already confirmed upstream (bug families:
# F1 late length guard = node_exporter#3848, F3 ignored acquire + deferred release = gvisor#15632,
# F4 nil checked before err = kube-state-metrics#3143). A signal orders the triage; it never changes a status.
FAMILY_CONFIDENCE = 0.9
_PARSE_FUNCS = {"strconv.ParseFloat", "strconv.ParseInt", "strconv.ParseUint", "strconv.Atoi", "strconv.ParseBool"}
SUBMATCH_METHODS = {"FindStringSubmatch", "FindSubmatch"}   # nil when no match, else len = 1 + groups
SPLIT_FUNCS = {"Split", "SplitN", "SplitAfter", "SplitAfterN", "Fields", "FieldsFunc"}
SPLIT_PKGS = {"strings", "bytes"}
_EXITS = {"return_statement", "break_statement", "continue_statement", "goto_statement"}
_EXIT_CALLS = {"panic", "os.Exit", "log.Fatal", "log.Fatalf", "log.Fatalln", "log.Panic", "log.Panicf"}
_NEG = {">": "<=", ">=": "<", "==": "!=", "!=": "==", "<": ">=", "<=": ">"}
_FLIP = {">": "<", ">=": "<=", "==": "==", "!=": "!=", "<": ">", "<=": ">="}


def _error_positions(fn: gd.GoFunction) -> list[int]:
    return [i for i, t in enumerate(gd._result_types(fn.result)) if t is not None and gd._t(t) == "error"]


def _never_fails(fn: gd.GoFunction, pos: int) -> int | None:
    """Number of returns if EVERY return statement of fn yields a literal `nil` at result `pos`, else None.
    Bare returns, forwarded calls (`return g()`) and closures' returns are not proofs."""
    count = 0
    for n in gd._walk(fn.body) if fn.body is not None else []:
        if n.type != "return_statement":
            continue
        kids = gd._named(n)
        exprs = gd._named(kids[0]) if kids and kids[0].type == "expression_list" else kids
        if len(exprs) <= pos or exprs[pos].type != "nil":
            return None
        count += 1
    return count or None


class _Detector:
    def __init__(self, root: Path, include_tests: bool = False):
        self.ix = gd.GoIndex(Path(root), include_tests=include_tests)
        self.df = gd.GoDataflow(self.ix, sinks=())          # resolution only: no sources, no sinks
        self.root = self.ix.root
        self.out: list[BugCandidate] = []
        self.suppressed: list[BugCandidate] = []   # sites a guard proves safe (kept to explain disappearances)
        self.proofs: list[dict] = []               # parallel to `suppressed`
        self._pkg_regexps: dict = {}               # package -> {var name: [pattern literal node or None]}

    # ---- helpers
    def _snippet(self, file: str, line: int, last: int | None = None) -> str:
        src = _lines(self.root / file)
        if not src:
            return ""
        a, b = max(1, line - SNIPPET_RADIUS), min(len(src), (last or line) + SNIPPET_RADIUS)
        return _numbered(src, a, b, set())

    def _ctx(self, key: str, kind: str) -> dict:
        fn = self.ix.functions[key]
        return {"kind": kind, "file": fn.file, "start": fn.start_line, "end": fn.end_line}

    def _resolved(self, key: str, call_node) -> str | None:
        site = self.df.facts(key).by_node.get((call_node.start_byte, call_node.end_byte))
        return site.callee if site is not None and site.resolution == "resolved" else None

    # ---- ignored-error
    def ignored_errors(self, key: str) -> None:
        fn = self.ix.functions[key]
        for site in self.df.facts(key).calls:
            if site.resolution != "resolved":
                continue
            callee = self.ix.functions[site.callee]
            epos = _error_positions(callee)
            if not epos:
                continue
            call, parent = site.node, site.node.parent
            ambiguity: list[str] = []
            if parent.type == "expression_statement":
                pass
            elif parent.type in ("defer_statement", "go_statement"):
                ambiguity.append(f"`{parent.type.split('_')[0]}` call: the error cannot be checked inline "
                                 "(intent unknown)")
            elif parent.type == "expression_list" and parent.parent is not None and \
                    parent.parent.type == "assignment_statement" and \
                    parent.parent.child_by_field_name("right") == parent and len(gd._named(parent)) == 1:
                left = gd._named(parent.parent.child_by_field_name("left"))
                if not all(i < len(left) and gd._t(left[i]) == "_" for i in epos):
                    continue
                ambiguity.append("explicit discard `_ =`: may be deliberate")
            else:
                continue                                   # result is used: not this pattern
            if callee.receiver_type and callee.name in TEARDOWN_METHODS:
                ambiguity.append(f"error of a {callee.name}() method: teardown errors are often deliberately "
                                 "best-effort")
            negative = []
            n = _never_fails(callee, epos[-1])
            if n:
                negative.append(f"{callee.display} returns a literal nil error in all {n} return statement(s)")
            line, _ = gd._pos(call)
            release = self._deferred_release(key, call, parent) if parent.type == "expression_statement" else None
            family = (f"; the next statement `{release[:60]}` defers a release on the same receiver that assumes "
                      "this call succeeded [family: ignored-acquire-deferred-release]") if release else ""
            self.out.append(BugCandidate(
                file=fn.file, line=line, category="ignored-error", rule="go.ignored-error.local-callee",
                function=fn.display,
                explanation=BUG_EXPLAIN["ignored-error"],
                suspicion=f"the error returned by {callee.display} (declared at {callee.file}:{callee.start_line}) "
                          f"is discarded at {site.callee_text}(..){family}",
                snippet=self._snippet(fn.file, line),
                confidence=FAMILY_CONFIDENCE if release and not ambiguity and not negative else _PRIOR["ignored-error"],
                related_lines=[line], negative_evidence=negative, ambiguity=ambiguity,
                context=[self._ctx(key, "function"), self._ctx(site.callee, "callee")]))

    # ---- overwritten-error
    @staticmethod
    def _err_write(stmt):
        """(assignment node, rhs call or None) when stmt plainly assigns `err` (`=` / `:=`)."""
        if stmt.type == "labeled_statement":
            inner = [c for c in gd._named(stmt) if c.type != "label_name"]
            stmt = inner[0] if inner else stmt
        if stmt.type not in ("assignment_statement", "short_var_declaration"):
            return None
        op = stmt.child_by_field_name("operator")
        if op is not None and gd._t(op) != "=":
            return None
        left = gd._named(stmt.child_by_field_name("left"))
        if not any(c.type == "identifier" and gd._t(c) == ERR_NAME for c in left):
            return None
        right = gd._named(stmt.child_by_field_name("right"))
        return stmt, (right[0] if len(right) == 1 and right[0].type == "call_expression" else None)

    @staticmethod
    def _err_uses(node):
        """(uses outside closures, uses inside closures) of identifier `err` under node."""
        plain = closure = 0
        stack = [(node, False)]
        while stack:
            n, in_fl = stack.pop()
            if n.type == "identifier" and gd._t(n) == ERR_NAME:
                closure, plain = (closure + 1, plain) if in_fl else (closure, plain + 1)
            stack.extend((c, in_fl or n.type == "func_literal") for c in n.children)
        return plain, closure

    def overwritten_errors(self, key: str) -> None:
        fn = self.ix.functions[key]
        if fn.body is None:
            return
        has_goto = any(n.type == "goto_statement" for n in gd._walk(fn.body))
        for sl in (n for n in gd._walk(fn.body) if n.type == "statement_list"):
            stmts = gd._named(sl)
            for i, s in enumerate(stmts):
                w = self._err_write(s)
                if w is None or w[1] is None:
                    continue
                first, call = w
                closure_uses = 0
                for j in range(i + 1, len(stmts)):
                    w2 = self._err_write(stmts[j])
                    if w2 is not None:
                        plain, clo = self._err_uses(w2[0].child_by_field_name("right"))
                        if plain:
                            break                      # the overwrite reads the previous value
                        closure_uses += clo
                        self._overwrite(key, fn, first, call, w2[0], closure_uses, has_goto)
                        break
                    plain, clo = self._err_uses(stmts[j])
                    if plain:
                        break                          # read (or nested write) before any overwrite
                    closure_uses += clo

    # ---- unchecked-split-index
    def _split_call(self, fn: gd.GoFunction, e):
        """(label, guaranteed minimum length, source arg, sep literal) if e is a strings/bytes split call."""
        if e is None or e.type != "call_expression":
            return None
        func = e.child_by_field_name("function")
        if func.type != "selector_expression" or func.child_by_field_name("operand").type != "identifier":
            return None
        pkg = self.ix.fn_file[fn.key].imports.get(gd._t(func.child_by_field_name("operand")))
        name = gd._t(func.child_by_field_name("field"))
        if pkg not in SPLIT_PKGS or name not in SPLIT_FUNCS:
            return None
        args = gd._named(e.child_by_field_name("arguments"))
        sep = _lit(args[1]) if len(args) > 1 and name.startswith("Split") and args[1].type != "rune_literal" \
            else None
        lo = 0
        if name.startswith("Split") and sep:                      # non-empty literal separator
            n = _int(args[2]) if name.endswith("N") and len(args) > 2 else -1
            lo = 0 if n == 0 or (name.endswith("N") and n is None) else 1
        return f"{pkg}.{name}", lo, (args[0] if args else None), sep

    def split_indexes(self, key: str) -> None:
        fn = self.ix.functions[key]
        if fn.body is None:
            return
        facts = self.df.facts(key)
        for ix in (n for n in gd._walk(fn.body) if n.type == "index_expression"):
            k = _int(ix.child_by_field_name("index"))
            operand = ix.child_by_field_name("operand")
            if k is None or operand is None:
                continue
            if operand.type == "call_expression":                  # strings.Split(..)[k]
                info = self._split_call(fn, operand)
                if info is None or k < info[1]:
                    continue
                var, d, call, ambiguity = None, None, operand, []
            elif operand.type == "identifier":
                var = gd._t(operand)
                defs, _ = self.df._reaching(var, ix, facts)
                splits = [d for d in defs if self._split_call(fn, d.rhs) is not None]
                if not splits:
                    continue
                d = max(splits, key=lambda d: d.pos)
                call, info = d.rhs, self._split_call(fn, d.rhs)
                ambiguity = [f"{var} is redefined between the split and the index"] if len(defs) > 1 else []
            else:
                continue
            definite, indefinite = self._conditions(fn, ix)
            ln, unmodelled = _Len(), []
            if var is not None:
                after = _guard_start(fn, var, ix, d, ambiguity)
                self._len_facts(fn, after, var, definite, indefinite, ln, unmodelled)
            occ = self._separator_occurrences(fn, ix, call, info, definite)
            floor = info[1]
            if occ:
                floor = max(floor, self._split_cap(call, occ + 1))
            if ln.bound(floor) > k:                                # protection proven: trace only, no candidate
                self._split_candidate(key, fn, ix, k, var, call, info, ambiguity, d, ln.used,
                                      proof={"kind": "guard_recognized", "index": k, "proven_len": ln.bound(floor),
                                             "guards": [g[:120] for g in ln.used[:3]], "separator_checks": occ})
                continue
            if unmodelled:
                ambiguity.append(f"len({var}) is compared to a non-constant or in a form not modelled: "
                                 f"{unmodelled[0][:80]}")
            if info[2] is not None and info[2].type == "identifier" and \
                    any(x is not None and x is not False for x in _later_writes(fn, gd._t(info[2]), call)):
                ambiguity.append(f"the split input {gd._t(info[2])} is written later (enclosing loop or closure): "
                                 "checks made before it do not hold at every evaluation")
            unknown = self._unrecognised_checks(info, definite)
            if unknown:
                ambiguity.append(f"the split input {gd._t(info[2])} is checked by {unknown[:80]} before the access "
                                 "(not modelled)")
            self._split_candidate(key, fn, ix, k, var, call, info, ambiguity, d, ln.used)

    # ---- unchecked-submatch-index
    def _submatch_call(self, e):
        """(receiver node, method, input node) for `X.FindStringSubmatch(in)` / `X.FindSubmatch(in)`."""
        e = _strip(e)
        if e is None or e.type != "call_expression":
            return None
        f = e.child_by_field_name("function")
        if f.type != "selector_expression" or gd._t(f.child_by_field_name("field")) not in SUBMATCH_METHODS:
            return None
        args = gd._named(e.child_by_field_name("arguments"))
        return f.child_by_field_name("operand"), gd._t(f.child_by_field_name("field")), (args[0] if args else None)

    def _compile_literal(self, fn_or_file, e):
        """Pattern literal node of `regexp.MustCompile(lit)` / `regexp.Compile(lit)`, else None."""
        e = _strip(e)
        if e is None or e.type != "call_expression":
            return None
        f = e.child_by_field_name("function")
        if f.type != "selector_expression" or f.child_by_field_name("operand").type != "identifier" or \
                gd._t(f.child_by_field_name("field")) not in ("MustCompile", "Compile", "MustCompilePOSIX"):
            return None
        if fn_or_file.imports.get(gd._t(f.child_by_field_name("operand"))) != "regexp":
            return None
        args = gd._named(e.child_by_field_name("arguments"))
        return args[0] if len(args) == 1 and args[0].type in ("interpreted_string_literal",
                                                               "raw_string_literal") else None

    def _package_regexps(self, pkg) -> dict:
        """Package-level `var X = regexp.MustCompile(lit)` (also grouped var blocks), and every name assigned
        anywhere else in the package at top level or in a function (then the value is not trusted: None)."""
        if pkg in self._pkg_regexps:
            return self._pkg_regexps[pkg]
        out: dict = {}
        parser = gd._parser()
        for rel, f in self.ix.files.items():
            if f.pkg != pkg:
                continue
            tree = parser.parse((self.root / rel).read_bytes())
            for n in gd._walk(tree.root_node, skip_func_literals=False):
                if n.type == "var_spec" and n.parent is not None and \
                        (n.parent.type == "var_declaration" and n.parent.parent == tree.root_node or
                         n.parent.type == "var_spec_list" and n.parent.parent.parent == tree.root_node):
                    names = n.children_by_field_name("name")
                    value = n.child_by_field_name("value")
                    vals = gd._named(value) if value is not None else []
                    for i, nm in enumerate(names):
                        lit = self._compile_literal(f, vals[i]) if len(vals) == len(names) else None
                        out.setdefault(gd._t(nm), []).append(lit)
                elif n.type == "assignment_statement":
                    for c in gd._named(n.child_by_field_name("left")):
                        if c.type == "identifier":
                            out.setdefault(gd._t(c), []).append(None)
        self._pkg_regexps[pkg] = out
        return out

    def _regexp_pattern(self, fn, recv, at):
        """(pattern value or None, confirmed receiver) for the regexp receiver of a submatch call."""
        if recv is None or recv.type != "identifier":
            return None, False
        name, f = gd._t(recv), self.ix.fn_file[fn.key]
        facts = self.df.facts(fn.key)
        defs, param = self.df._reaching(name, at, facts)
        if defs or name in facts.locals:
            if param or len(defs) != 1 or defs[0].ret_index:
                return None, False
            lit = self._compile_literal(f, defs[0].rhs)
        else:
            lits = self._package_regexps(f.pkg).get(name, [])
            lit = lits[0] if len(lits) == 1 else None
        if lit is None:
            return None, False
        return _pattern_value(lit), True

    def submatch_indexes(self, key: str) -> None:
        fn = self.ix.functions[key]
        if fn.body is None:
            return
        facts = self.df.facts(key)
        for ix in (n for n in gd._walk(fn.body) if n.type == "index_expression"):
            k = _int(ix.child_by_field_name("index"))
            operand = ix.child_by_field_name("operand")
            if k is None or operand is None:
                continue
            ambiguity: list[str] = []
            if operand.type == "call_expression":
                info = self._submatch_call(operand)
                if info is None:
                    continue
                var, call, after = None, _strip(operand), ix.start_byte
            elif operand.type == "identifier":
                var = gd._t(operand)
                defs, _ = self.df._reaching(var, ix, facts)
                subs = [d for d in defs if self._submatch_call(d.rhs) is not None]
                if not subs:
                    continue
                d = max(subs, key=lambda d: d.pos)
                call, info = _strip(d.rhs), self._submatch_call(d.rhs)
                if len(defs) > 1:
                    ambiguity.append(f"{var} is redefined between the match and the index")
                after = _guard_start(fn, var, ix, d, ambiguity)
            else:
                continue
            recv, method, inp = info
            pattern, confirmed = self._regexp_pattern(fn, recv, call)
            groups = _groups(pattern)
            definite, indefinite = self._conditions(fn, ix)
            ln, unmodelled = _Len(), []
            nonnil: list[str] = []
            if var is not None:
                self._len_facts(fn, after, var, definite, indefinite, ln, unmodelled)
                for atom, truth in definite:
                    if not isinstance(atom, tuple) and atom.start_byte >= after and _nil_check(atom, var, truth):
                        nonnil.append(gd._t(atom) if truth else f"not ({gd._t(atom)})")
            nonnil += self._match_checks(fn, definite, recv, inp, call)
            if ln.bound(0) >= 1:
                nonnil.append(ln.used[0] if ln.used else "len > 0")
            proven = ln.bound(0) > k or (nonnil and groups is not None and k <= groups)
            what = f"{var}[{k}]" if var else gd._t(ix)[:60]
            if proven:
                self._submatch_candidate(key, fn, ix, k, what, call, method, groups, ambiguity, nonnil,
                                         proof={"kind": "guard_recognized", "index": k, "groups": groups,
                                                "proven_len": ln.bound(0),
                                                "guards": [g[:120] for g in dict.fromkeys(ln.used + nonnil)][:3]})
                continue
            if nonnil and groups is None:
                ambiguity.append(f"{what}: match proven ({nonnil[0][:60]}) but the group count of the pattern "
                                 "is unknown")
            if not nonnil:
                if not confirmed:
                    ambiguity.append(f"receiver {gd._t(recv)[:40]} is not proven to be regexp.MustCompile/Compile "
                                     "of a literal pattern")
                elif pattern is None or groups is None:
                    ambiguity.append("pattern could not be checked (escape or syntax not supported)")
                elif _matches_empty(pattern):
                    ambiguity.append(f"pattern `{pattern[:60]}` matches the empty string: it may never fail")
                if unmodelled:
                    ambiguity.append(f"len({var}) is compared to a non-constant or in a form not modelled: "
                                     f"{unmodelled[0][:80]}")
                if inp is not None and _lit(inp) is not None:
                    ambiguity.append("constant input: the match result is fixed")
                if inp is not None and inp.type == "identifier":
                    unknown = self._unrecognised_checks((None, None, inp, None), definite)
                    if unknown:
                        ambiguity.append(f"the input {gd._t(inp)} is checked by {unknown[:80]} before the access "
                                         "(not modelled)")
                    if any(x is not None and x is not False for x in _later_writes(fn, gd._t(inp), call)):
                        ambiguity.append(f"the input {gd._t(inp)} is written later (enclosing loop or closure)")
            self._submatch_candidate(key, fn, ix, k, what, call, method, groups, ambiguity, nonnil)

    def _match_checks(self, fn, definite, recv, inp, call) -> list[str]:
        """`re.MatchString(x)` / `re.Match(x)` known true, same regexp variable and same input value."""
        out = []
        if recv is None or recv.type != "identifier" or inp is None or inp.type != "identifier":
            return out
        for atom, truth in definite:
            if isinstance(atom, tuple) or not truth:
                continue
            a = _strip(atom)
            if a.type != "call_expression":
                continue
            f = a.child_by_field_name("function")
            args = gd._named(a.child_by_field_name("arguments"))
            if f.type != "selector_expression" or gd._t(f.child_by_field_name("field")) not in ("MatchString",
                                                                                                "Match") \
                    or len(args) != 1 or args[0].type != "identifier":
                continue
            r = f.child_by_field_name("operand")
            if r.type == "identifier" and self._same_value(fn, gd._t(r), a, gd._t(recv), call) and \
                    self._same_value(fn, gd._t(args[0]), a, gd._t(inp), call):
                out.append(gd._t(atom))
        return out

    def _submatch_candidate(self, key, fn, ix, k, what, call, method, groups, ambiguity, nonnil,
                            proof=None) -> None:
        line, _ = gd._pos(ix)
        if nonnil and groups is not None and k > groups:
            susp = (f"{what} reads group {k} of {method}(..) but the pattern has only {groups} group(s): "
                    f"panics whenever it matches (match proven by {nonnil[0][:60]})")
        else:
            susp = (f"{what} reads index {k} of {method}(..), which is nil when the input does not match, with no "
                    f"check proving a match (m != nil / len(m) > {k} / MatchString)")
        (self.out if proof is None else self.suppressed).append(BugCandidate(
            file=fn.file, line=line, category="unchecked-submatch-index", rule="go.unchecked-submatch-index",
            function=fn.display, explanation=BUG_EXPLAIN["unchecked-submatch-index"], suspicion=susp,
            snippet=self._snippet(fn.file, line), confidence=_PRIOR["unchecked-submatch-index"],
            related_lines=sorted({gd._pos(call)[0], line}), negative_evidence=[], ambiguity=ambiguity,
            context=[self._ctx(key, "function")]))
        if proof is not None:
            self.proofs.append(proof)

    # ---- facts true at a node
    def _conditions(self, fn: gd.GoFunction, node) -> tuple[list, list]:
        """(definite atoms [(expr, truth)], indefinite exprs) holding when `node` is evaluated: short-circuit
        operands on the left, enclosing if/else, tagless switch cases (earlier cases false), early exits."""
        definite: list = []
        indefinite: list = []
        cur = node
        while cur is not None and cur != fn.body:
            par = cur.parent
            if par is None or cur.type == "func_literal":
                break
            if par.type == "binary_expression" and _op(par) in ("&&", "||") and \
                    cur == par.child_by_field_name("right"):
                _decompose(par.child_by_field_name("left"), _op(par) == "&&", definite, indefinite)
            elif par.type == "if_statement" and par.child_by_field_name("condition") is not None:
                cond = par.child_by_field_name("condition")
                if cur == par.child_by_field_name("consequence"):
                    _decompose(cond, True, definite, indefinite)
                elif cur == par.child_by_field_name("alternative"):
                    _decompose(cond, False, definite, indefinite)
            elif cur.type in ("expression_case", "default_case") and par.type == "expression_switch_statement":
                cases = [c for c in gd._named(par) if c.type in ("expression_case", "default_case")]
                value = par.child_by_field_name("value")
                i = cases.index(cur)
                if i and _falls_through(cases[i - 1]):
                    pass                                           # entered from the previous case: no fact
                elif value is None:                                  # tagless: switch { case cond: ... }
                    for other in cases:
                        if other == cur:
                            break
                        if other.type == "expression_case":
                            for v in gd._named(other.child_by_field_name("value")):
                                _decompose(v, False, definite, indefinite)
                    if cur.type == "default_case":
                        for other in cases[cases.index(cur) + 1:]:
                            if other.type == "expression_case":
                                for v in gd._named(other.child_by_field_name("value")):
                                    _decompose(v, False, definite, indefinite)
                    else:
                        vals = gd._named(cur.child_by_field_name("value"))
                        if len(vals) == 1:
                            _decompose(vals[0], True, definite, indefinite)
                        else:
                            indefinite.extend(vals)                # case a, b: a disjunction
                elif cur.type == "expression_case":
                    definite.append((("switch_value", value, gd._named(cur.child_by_field_name("value"))), True))
            cur = par
        for n in gd._walk(fn.body):                                # early exits before the node
            if n.type != "if_statement" or n.end_byte > node.start_byte or not gd._contains(n.parent, node):
                continue
            if n.child_by_field_name("alternative") is not None:
                continue
            cond = n.child_by_field_name("condition")
            if cond is not None and _terminates(n.child_by_field_name("consequence"),
                                                lambda call: self._never_returns(fn.key, call)):
                _decompose(cond, False, definite, indefinite)
        return definite, indefinite

    def _len_facts(self, fn, after: int, var: str, definite, indefinite, ln: _Len, unmodelled: list) -> None:
        # a guard written before `after` (the split, or the start of a loop that rewrites var) may be about
        # another value of var
        aliases = _len_aliases(fn, var, after)
        for atom, truth in definite:
            if isinstance(atom, tuple):
                _, value, vals = atom
                if _is_len_of(value, var, aliases) and value.start_byte >= after:
                    ints = [_int(v) for v in vals]
                    if ints and None not in ints:
                        ln.add(">=", min(ints), f"case {', '.join(map(str, ints))}")
                    else:
                        unmodelled.append(gd._t(atom[1])[:60])
                continue
            if atom.start_byte < after or not any(_is_len_of(n, var, aliases) for n in gd._walk(atom)):
                continue
            c = self._len_cmp(atom, var, aliases)
            if c is None:
                unmodelled.append(gd._t(atom))
                continue
            op, n = c
            ln.add(op if truth else _NEG[op], n, gd._t(atom) if truth else f"not ({gd._t(atom)})")
        for e in indefinite:
            if e.start_byte >= after and any(_is_len_of(n, var, aliases) for n in gd._walk(e)):
                unmodelled.append(gd._t(e))

    @staticmethod
    def _len_cmp(e, var: str, aliases: frozenset = frozenset()):
        e = _strip(e)
        if e.type != "binary_expression" or _op(e) not in _NEG:
            return None
        left, right = e.child_by_field_name("left"), e.child_by_field_name("right")
        if _is_len_of(left, var, aliases) and _int(right) is not None:
            return _op(e), _int(right)
        if _is_len_of(right, var, aliases) and _int(left) is not None:
            return _FLIP[_op(e)], _int(left)
        return None

    def _strings_call(self, fn, e):
        """(name, args) when e is a call to the standard strings package."""
        e = _strip(e)
        if e is None or e.type != "call_expression":
            return None
        f = e.child_by_field_name("function")
        if f.type != "selector_expression" or f.child_by_field_name("operand").type != "identifier":
            return None
        if self.ix.fn_file[fn.key].imports.get(gd._t(f.child_by_field_name("operand"))) != "strings":
            return None
        return gd._t(f.child_by_field_name("field")), gd._named(e.child_by_field_name("arguments"))

    def _presence(self, fn, atom, truth: bool) -> list[tuple[str, str, int, str, object]]:
        """Separator-presence facts from one atom: [(input name, literal, min occurrences, kind, node)].
        kind 'exact' = the literal itself; 'prefix' = a prefix/suffix that contains the separator."""
        out = []
        sc = self._strings_call(fn, atom)
        if sc and truth:
            name, args = sc
            if len(args) == 2 and args[0].type == "identifier" and _lit(args[1]) is not None:
                lit = _lit(args[1])
                if name in ("Contains", "ContainsRune") or (name == "ContainsAny" and len(lit) == 1):
                    out.append((gd._t(args[0]), lit, 1, "exact", atom))
                elif name in ("HasPrefix", "HasSuffix"):
                    out.append((gd._t(args[0]), lit, 1, "prefix", atom))
            return out
        a = _strip(atom)
        if a.type != "binary_expression" or _op(a) not in _NEG:
            return out
        op = _op(a) if truth else _NEG[_op(a)]
        left, right = a.child_by_field_name("left"), a.child_by_field_name("right")
        if _int(right) is None and _int(left) is not None:
            left, right, op = right, left, _FLIP[op]
        kk = self._signed_int(right)
        if kk is None:
            return out
        target = self._index_source(fn, left, atom)
        if target is None:
            return out
        fname, name, lit, at = target                               # at: where the input was read
        if fname == "Count":
            occ = {">": kk + 1, ">=": kk, "==": kk}.get(op)
            if occ and occ > 0:
                out.append((name, lit, occ, "exact", at))
        elif (op == "!=" and kk == -1) or (op == ">" and kk >= -1) or (op in (">=", "==") and kk >= 0):
            out.append((name, lit, 1, "exact", at))                 # Index result >= 0: found
        return out

    @staticmethod
    def _signed_int(n):
        n = _strip(n)
        if n is not None and n.type == "unary_expression" and _op(n) == "-":
            v = _int(n.child_by_field_name("operand"))
            return -v if v is not None else None
        return _int(n)

    def _index_source(self, fn, e, at):
        """('Index'|'Count', input name, literal, call node) for strings.Index/Count(x, lit), directly or through
        a local whose only reaching definition is such a call (the call node is where x was read)."""
        e = _strip(e)
        if e is not None and e.type == "identifier":
            defs, param = self.df._reaching(gd._t(e), at, self.df.facts(fn.key))
            if param or len(defs) != 1 or defs[0].ret_index:
                return None
            e = defs[0].rhs
        sc = self._strings_call(fn, e)
        if not sc:
            return None
        name, args = sc
        if (name in _INDEX_FUNCS or name == "Count") and len(args) == 2 and args[0].type == "identifier" \
                and _lit(args[1]) is not None:
            if name.endswith("Any") and len(_lit(args[1])) != 1:
                return None                                        # any ONE of the characters: no proof
            return ("Count" if name == "Count" else "Index"), gd._t(args[0]), _lit(args[1]), _strip(e)
        return None

    def _same_value(self, fn, name: str, at, src: str, split_call) -> bool:
        """`name` evaluated at `at` holds the same string as `src` at the split call: the same variable with
        the same reaching definitions, or a simple alias (`v := src`) whose source was not reassigned."""
        facts = self.df.facts(fn.key)
        boundary, by_closure = _later_writes(fn, src, split_call)
        if by_closure or (boundary is not None and at.start_byte < boundary):
            return False                                           # the check may see an older value

        def rd(n, node):
            d, p = self.df._reaching(n, node, facts)
            return tuple(sorted(x.pos for x in d)), p
        if name == src:
            return rd(src, at) == rd(src, split_call)
        defs, param = self.df._reaching(name, at, facts)
        if param or len(defs) != 1 or defs[0].rhs is None or defs[0].rhs.type != "identifier" or \
                gd._t(defs[0].rhs) != src:
            return False
        return rd(src, defs[0].node) == rd(src, split_call)

    def _occurrences(self, fn, definite, src: str, lit: str, split_call) -> int:
        best = 0
        for atom, truth in definite:
            if isinstance(atom, tuple):
                continue
            for name, l, n, kind, node in self._presence(fn, atom, truth):
                hits = n if (kind == "exact" and l == lit) else (l.count(lit) if kind == "prefix" and lit else 0)
                if hits and self._same_value(fn, name, node, src, split_call):
                    best = max(best, hits)
        return best

    def _separator_occurrences(self, fn, ix, call, info, definite) -> int:
        """Proven minimum number of separator occurrences in the split input (0 = nothing proven)."""
        label, _, src, sep = info
        if src is None or src.type != "identifier" or not label.split(".")[1].startswith("Split"):
            return 0
        args = gd._named(call.child_by_field_name("arguments"))
        if sep:
            return self._occurrences(fn, definite, gd._t(src), sep, call)
        if len(args) < 2 or args[1].type != "identifier":
            return 0
        sv = gd._t(args[1])                                        # separator held in a variable
        defs, param = self.df._reaching(sv, call, self.df.facts(fn.key))
        if param or not defs:
            return 0
        nonempty = any(not isinstance(a, tuple) and self._is_nonempty(a, t, sv) for a, t in definite)
        counts = []
        for d in defs:
            val = _lit(d.rhs)
            if val is None:
                return 0                                           # value not a literal: cannot prove
            if val == "":
                if nonempty:
                    continue
                return 0
            at_def, _ = self._conditions(fn, d.node)
            n = self._occurrences(fn, at_def, gd._t(src), val, call)
            if not n:
                return 0
            counts.append(n)
        return min(counts) if counts else 0

    @staticmethod
    def _is_nonempty(atom, truth: bool, name: str) -> bool:
        a = _strip(atom)
        if a.type != "binary_expression" or _op(a) not in ("==", "!="):
            return False
        l, r = a.child_by_field_name("left"), a.child_by_field_name("right")
        if not ((l.type == "identifier" and gd._t(l) == name and _lit(r) == "") or
                (r.type == "identifier" and gd._t(r) == name and _lit(l) == "")):
            return False
        return (_op(a) == "!=") == truth

    @staticmethod
    def _split_cap(call, wanted: int) -> int:
        """Elements a split can actually yield, given `wanted` from separator occurrences (SplitN limit)."""
        f = gd._t(call.child_by_field_name("function").child_by_field_name("field"))
        args = gd._named(call.child_by_field_name("arguments"))
        if f.endswith("N"):
            n = _int(args[2]) if len(args) > 2 else None
            if n is None:
                return 0
            return wanted if n < 0 else min(wanted, n)
        return wanted

    def _unrecognised_checks(self, info, definite) -> str | None:
        """A call taking the split input in a condition that holds at the access but that is not one of the
        modelled separator checks (custom validator, regexp...): may protect, cannot be proven."""
        src = info[2]
        if src is None or src.type != "identifier":
            return None
        name = gd._t(src)
        for atom, _ in definite:
            if isinstance(atom, tuple):
                continue
            for c in gd._walk(atom):
                if c.type != "call_expression" or gd._t(c.child_by_field_name("function")) == "len":
                    continue
                f = c.child_by_field_name("function")
                field = f.child_by_field_name("field") if f.type == "selector_expression" else None
                if field is not None and gd._t(field) in _SEP_CHECKS:
                    continue                                       # modelled: proves or does not
                if any(a.type == "identifier" and gd._t(a) == name
                       for a in gd._named(c.child_by_field_name("arguments"))):
                    return gd._t(atom)
        return None

    def _never_returns(self, key: str, call) -> bool:
        """Call to a uniquely resolved module function whose body ends with an exit call (one level, e.g.
        `func fail(msg string) { fmt.Println(msg); os.Exit(1) }`)."""
        callee = self._resolved(key, call)
        if callee is None or self.ix.functions[callee].body is None:
            return False
        body = self.ix.functions[callee].body
        stmts = gd._named(gd._named(body)[0]) if gd._named(body) and gd._named(body)[0].type == "statement_list" \
            else []
        return bool(stmts) and stmts[-1].type == "expression_statement" and _exit_call(stmts[-1])

    @staticmethod
    def _late_len_check(fn, ix, var: str) -> int | None:
        """Line of the first `len(var)` evaluated after the access in the same function body (not in a closure)."""
        for n in gd._walk(fn.body):
            if n.type != "call_expression" or n.start_byte <= ix.end_byte:
                continue
            f, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
            if f is None or gd._t(f) != "len" or args is None:
                continue
            a = gd._named(args)
            if len(a) == 1 and gd._t(a[0]) == var and not _in_closure(n, fn.body):
                return gd._pos(n)[0]
        return None

    @staticmethod
    def _discarded_parse(ix) -> str | None:
        """`v, _ := strconv.ParseX(<ix>, ..)`: the indexed element feeds a parse whose error is thrown away."""
        args = ix.parent
        if args is None or args.type != "argument_list":
            return None
        call = args.parent
        f = call.child_by_field_name("function") if call is not None else None
        if f is None or gd._t(f) not in _PARSE_FUNCS:
            return None
        lst = call.parent
        stmt = lst.parent if lst is not None and lst.type == "expression_list" else None
        if stmt is None or stmt.type not in ("short_var_declaration", "assignment_statement") or \
                stmt.child_by_field_name("right") != lst:
            return None
        left = gd._named(stmt.child_by_field_name("left"))
        return gd._t(f) if len(left) == 2 and gd._t(left[1]) == "_" else None

    def _deferred_release(self, key, call, stmt) -> str | None:
        """`x.acquire()` as a statement immediately followed by `defer x.<m>()` on the same receiver x, where the
        resolved release method can panic (asserts the acquire succeeded): an unchecked failed acquire then
        crashes in the deferred release."""
        f = call.child_by_field_name("function")
        if f is None or f.type != "selector_expression":
            return None
        recv = gd._t(f.child_by_field_name("operand"))
        nxt = _next_stmt(stmt)
        if nxt is None or nxt.type != "defer_statement":
            return None
        dc = next((c for c in gd._named(nxt) if c.type == "call_expression"), None)
        df = dc.child_by_field_name("function") if dc is not None else None
        if df is None or df.type != "selector_expression" or gd._t(df.child_by_field_name("operand")) != recv:
            return None
        callee = self._resolved(key, dc)
        body = self.ix.functions[callee].body if callee else None
        if body is None or not any(n.type == "call_expression" and gd._t(n.child_by_field_name("function")) == "panic"
                                   for n in gd._walk(body)):
            return None
        return gd._t(nxt)

    # ---- nil-before-err-check (family F4)
    def nil_before_err(self, key: str) -> None:
        """`v, err := f(); if v == nil { continue|return|break }` with `err` read only later: when f returns
        (nil, err) the error is skipped by the nil check."""
        fn = self.ix.functions[key]
        if fn.body is None:
            return
        for s1 in gd._walk(fn.body):
            if s1.type not in ("short_var_declaration", "assignment_statement"):
                continue
            left, right = s1.child_by_field_name("left"), s1.child_by_field_name("right")
            if left is None or right is None:
                continue
            names = [gd._t(x) for x in gd._named(left)]
            rhs = gd._named(right)
            if len(names) < 2 or names[-1] != ERR_NAME or len(rhs) != 1 or rhs[0].type != "call_expression":
                continue
            s2 = _next_stmt(s1)
            if s2 is None or s2.type != "if_statement" or s2.child_by_field_name("initializer") is not None:
                continue
            cond, body = s2.child_by_field_name("condition"), s2.child_by_field_name("consequence")
            if cond is None or body is None or s2.child_by_field_name("alternative") is not None:
                continue
            if cond.type != "binary_expression" or _op(cond) != "==":
                continue
            l, r = gd._t(cond.child_by_field_name("left")), gd._t(cond.child_by_field_name("right"))
            var = l if r == "nil" else r if l == "nil" else None
            if var not in names[:-1] or var == "_":
                continue
            stmts = [x for c in gd._named(body) for x in (gd._named(c) if c.type == "statement_list" else [c])
                     if x.type != "comment"]
            if not stmts or any(st.type not in _EXITS for st in stmts) or _mentions(body, ERR_NAME):
                continue
            later = next((n for n in gd._walk(fn.body) if n.type == "identifier" and gd._t(n) == ERR_NAME
                          and n.start_byte >= s2.end_byte and not _in_closure(n, fn.body)), None)
            if later is None or not _reads_same_err(later, s1, s2, fn.body):
                continue
            line, l2 = gd._pos(s1)[0], gd._pos(s2)[0]
            self.out.append(BugCandidate(
                file=fn.file, line=line, category="nil-before-err-check", rule="go.nil-before-err-check",
                function=fn.display, explanation=BUG_EXPLAIN["nil-before-err-check"],
                suspicion=f"`{var} == nil` is checked at line {l2} and exits before `{ERR_NAME}` (line "
                          f"{gd._pos(later)[0]}) is examined: if {gd._t(rhs[0].child_by_field_name('function'))}"
                          f"(..) returns ({var}=nil, {ERR_NAME}!=nil) the error is silently dropped",
                snippet=self._snippet(fn.file, line, gd._pos(later)[0]), confidence=_PRIOR["nil-before-err-check"],
                related_lines=[line, l2, gd._pos(later)[0]], context=[self._ctx(key, "function")]))

    def _split_candidate(self, key, fn, ix, k, var, call, info, ambiguity, d, guards, proof=None) -> None:
        label, lo, src, sep = info
        line, _ = gd._pos(ix)
        negative = []
        if k == 0 and sep is None and label.split(".")[1].startswith("Split"):
            ambiguity = ambiguity + ["separator is not a constant: index 0 only fails for an empty separator "
                                     "and an empty input"]
        lit = _lit(src) if src is not None and src.type != "rune_literal" else None
        if lit is not None and sep and "\\" not in lit + sep:          # escapes: text != value, no proof
            n = len(lit.split(sep)) if label.endswith(("Split", "SplitAfter")) else None
            if n is not None and n > k:
                negative.append(f'constant input "{lit}" splits into {n} element(s): index {k} exists')
        what = f"{var}[{k}]" if var else gd._t(ix)[:60]
        guard_txt = (f"; existing guard does not prove len > {k}: {guards[0][:80]}") if guards and not ambiguity \
            else ""
        late = self._late_len_check(fn, ix, var) if var and proof is None else None
        silent = self._discarded_parse(ix) if proof is None else None
        if silent:
            guard_txt += (f"; the element is passed to {silent} whose error is discarded: an input with the separator "
                          "elsewhere gives a silently wrong value [family: discarded-parse-error]")
        if late:
            guard_txt += (f"; a length check on {var} only appears AFTER the access (line {late}): the intended "
                          "guard comes too late [family: late-length-guard]")
        (self.out if proof is None else self.suppressed).append(BugCandidate(
            file=fn.file, line=line, category="unchecked-split-index", rule="go.unchecked-split-index",
            function=fn.display, explanation=BUG_EXPLAIN["unchecked-split-index"],
            suspicion=f"{what} reads index {k} of {label}(..) (guaranteed length {lo}) with no length check "
                      f"proving len > {k}{guard_txt}",
            snippet=self._snippet(fn.file, line),
            confidence=FAMILY_CONFIDENCE if (late or silent) and not ambiguity else _PRIOR["unchecked-split-index"],
            related_lines=sorted({gd._pos(call)[0], line} | ({late} if late else set())),
            negative_evidence=negative, ambiguity=ambiguity,
            context=[self._ctx(key, "function")]))
        if proof is not None:
            self.proofs.append(proof)

    def _overwrite(self, key, fn, first, call, second, closure_uses: int, has_goto: bool) -> None:
        l1, _ = gd._pos(first)
        l2, _ = gd._pos(second)
        ambiguity, negative, ctx = [], [], [self._ctx(key, "function")]
        if closure_uses:
            ambiguity.append(f"a closure between lines {l1} and {l2} captures {ERR_NAME} and may read it")
        if has_goto:
            ambiguity.append("the function contains goto: straight-line order is not a proof")
        callee = self._resolved(key, call)
        if callee is not None:
            ctx.append(self._ctx(callee, "callee"))
            epos = _error_positions(self.ix.functions[callee])
            left = gd._named(first.child_by_field_name("left"))
            idx = next(k for k, c in enumerate(left) if gd._t(c) == ERR_NAME)
            if idx in epos:
                n = _never_fails(self.ix.functions[callee], idx)
                if n:
                    negative.append(f"{self.ix.functions[callee].display} returns a literal nil error in all "
                                    f"{n} return statement(s)")
        self.out.append(BugCandidate(
            file=fn.file, line=l1, category="overwritten-error", rule="go.overwritten-error.straight-line",
            function=fn.display, explanation=BUG_EXPLAIN["overwritten-error"],
            suspicion=f"{ERR_NAME} assigned from {gd._t(call.child_by_field_name('function'))}(..) at line {l1} "
                      f"is overwritten at line {l2} with no read in between",
            snippet=self._snippet(fn.file, l1, l2), confidence=_PRIOR["overwritten-error"],
            related_lines=[l1, l2], negative_evidence=negative, ambiguity=ambiguity, context=ctx))


def _int(n) -> int | None:
    try:
        return int(gd._t(n), 0) if n is not None and n.type == "int_literal" else None
    except ValueError:
        return None


def _is_len_of(n, var: str, aliases: frozenset = frozenset()) -> bool:
    if n is not None and n.type == "identifier" and gd._t(n) in aliases:
        return True
    if n is None or n.type != "call_expression" or gd._t(n.child_by_field_name("function")) != "len":
        return False
    args = gd._named(n.child_by_field_name("arguments"))
    return len(args) == 1 and args[0].type == "identifier" and gd._t(args[0]) == var


def _len_aliases(fn: gd.GoFunction, var: str, after: int) -> frozenset:
    """Names declared once as `n := len(var)` / `var n = len(var)` at or after `after` (so about the value of var
    that reaches the access) and never written again anywhere in the function (closures included)."""
    decls: dict[str, list] = {}
    written: set[str] = set()
    for n in gd._walk(fn.body, skip_func_literals=False):
        if n.type in ("short_var_declaration", "var_spec"):
            names = gd._named(n.child_by_field_name("left")) if n.type == "short_var_declaration" else \
                [c for c in n.children_by_field_name("name")]
            values = gd._named(n.child_by_field_name("right" if n.type == "short_var_declaration" else "value"))
            for i, name in enumerate(names):
                if name.type == "identifier":
                    decls.setdefault(gd._t(name), []).append(
                        (n, values[i] if len(values) == len(names) else None))
        elif n.type == "assignment_statement":
            written.update(gd._t(c) for c in gd._named(n.child_by_field_name("left")) if c.type == "identifier")
        elif n.type in ("inc_statement", "dec_statement"):
            written.update(gd._t(c) for c in gd._named(n) if c.type == "identifier")
    return frozenset(name for name, ds in decls.items()
                     if len(ds) == 1 and name not in written and name != var and ds[0][1] is not None
                     and ds[0][0].start_byte >= after and _is_len_of(ds[0][1], var))


def _terminates(block, never_returns=lambda call: False) -> bool:
    stmts = gd._named(gd._named(block)[0]) if block is not None and gd._named(block) and \
        gd._named(block)[0].type == "statement_list" else []
    if not stmts:
        return False
    last = stmts[-1]
    if last.type in _EXITS:
        return True
    if last.type == "if_statement":                                # if/else where every branch exits
        return _if_terminates(last, never_returns)
    if last.type == "expression_statement" and gd._named(last) and gd._named(last)[0].type == "call_expression":
        return _exit_call(last) or never_returns(gd._named(last)[0])
    return False


def _exit_call(stmt) -> bool:
    """Expression statement calling a function that does not return (panic, os.Exit, log.Fatal, t.FailNow, ..)."""
    call = gd._named(stmt)[0] if gd._named(stmt) else None
    if call is None or call.type != "call_expression":
        return False
    fn = gd._t(call.child_by_field_name("function"))
    return fn in _EXIT_CALLS or fn.endswith((".Fatal", ".Fatalf", ".FailNow"))


def _if_terminates(stmt, never_returns) -> bool:
    """An if statement exits on every path: it has a final else and each branch (else-if chain included) exits."""
    alt = stmt.child_by_field_name("alternative")
    if alt is None or not _terminates(stmt.child_by_field_name("consequence"), never_returns):
        return False
    return _if_terminates(alt, never_returns) if alt.type == "if_statement" else _terminates(alt, never_returns)


_SEP_CHECKS = {"Contains", "ContainsRune", "ContainsAny", "HasPrefix", "HasSuffix", "Count", "Index", "IndexByte",
               "IndexRune", "IndexAny", "LastIndex", "LastIndexByte", "LastIndexAny"}
_INDEX_FUNCS = {"Index", "IndexByte", "IndexRune", "IndexAny", "LastIndex", "LastIndexByte", "LastIndexAny"}


def _strip(e):
    while e is not None and e.type == "parenthesized_expression" and gd._named(e):
        e = gd._named(e)[0]
    return e


def _op(e) -> str:
    o = e.child_by_field_name("operator")
    return gd._t(o) if o is not None else ""


def _decompose(e, truth: bool, definite: list, indefinite: list) -> None:
    """Split a condition known to evaluate to `truth` into atoms that are certainly true/false.
    `a && b` true / `a || b` false: both sides certain. `a && b` false / `a || b` true: nothing certain."""
    e = _strip(e)
    if e is None:
        return
    if e.type == "unary_expression" and _op(e) == "!":
        return _decompose(e.child_by_field_name("operand"), not truth, definite, indefinite)
    if e.type == "binary_expression" and _op(e) in ("&&", "||"):
        if (_op(e) == "&&") == truth:
            _decompose(e.child_by_field_name("left"), truth, definite, indefinite)
            _decompose(e.child_by_field_name("right"), truth, definite, indefinite)
        else:
            indefinite.append(e)
        return
    definite.append((e, truth))


def _lit(n) -> str | None:
    """Source text of a string / rune literal ('x' -> x) in interpreted-string escape form: a raw literal
    `\\n` (backslash, n) becomes \\\\n, so it never equals the newline "\\n". Different spellings of one value
    (\\x3a vs :) compare unequal: no proof, never a false one."""
    if n is None:
        return None
    if n.type == "rune_literal":
        return gd._t(n)[1:-1]
    if n.type == "raw_string_literal":
        return gd._t(n)[1:-1].replace("\\", "\\\\").replace('"', '\\"')
    return gd._string_literal(n)


def _pattern_value(lit) -> str | None:
    """Value of a Go string literal used as a regexp (raw: as is; interpreted: Go escapes decoded)."""
    text = gd._t(lit)[1:-1]
    if lit.type == "raw_string_literal":
        return text
    try:
        return ast.literal_eval('"' + text + '"') if text.isascii() else None
    except (ValueError, SyntaxError):
        return None


def _compiled(pattern: str | None):
    if pattern is None:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return re.compile(pattern)
    except (re.error, ValueError, OverflowError):
        return None                       # RE2-only syntax: no claim about groups


def _groups(pattern: str | None) -> int | None:
    c = _compiled(pattern)
    return c.groups if c is not None else None


def _matches_empty(pattern: str) -> bool:
    c = _compiled(pattern)
    return c is None or c.search("") is not None


def _nil_check(atom, var: str, truth: bool) -> bool:
    """`var != nil` known true, or `var == nil` known false."""
    a = _strip(atom)
    if a.type != "binary_expression" or _op(a) not in ("==", "!="):
        return False
    l, r = a.child_by_field_name("left"), a.child_by_field_name("right")
    if not ((l.type == "identifier" and gd._t(l) == var and r.type == "nil") or
            (r.type == "identifier" and gd._t(r) == var and l.type == "nil")):
        return False
    return (_op(a) == "!=") == truth


def _falls_through(case) -> bool:
    body = [c for c in gd._named(case) if c.type == "statement_list"]
    last = gd._named(body[-1])[-1] if body and gd._named(body[-1]) else None
    return last is not None and last.type == "fallthrough_statement"


def _guard_start(fn: gd.GoFunction, var: str, ix, d, ambiguity: list) -> int:
    """Byte offset from which a condition on var is about the value read at ix: after its definition, and after
    the start of a loop body that rewrites var later (back edge); never when a closure assigns var."""
    boundary, by_closure = _later_writes(fn, var, ix)
    if boundary is not None or by_closure:
        ambiguity.append(f"{var} is written later {'by a closure' if by_closure else 'in an enclosing loop'}: a later "
                         f"value of {var} may reach the access (guards before it do not count)")
    if by_closure:
        return ix.start_byte                                       # a closure may rewrite var at any time
    return d.assign.end_byte if boundary is None else max(d.assign.end_byte, boundary)


def _later_writes(fn: gd.GoFunction, var: str, node) -> tuple[int | None, bool]:
    """Writes `var = ..` that textual reaching definitions miss: (start byte of the body of the outermost loop
    enclosing `node` that rewrites var after it, or None; whether a closure (not enclosing node) assigns var).
    Over-approximate (a shadowing var of the same name counts): it only removes proofs."""
    boundary, by_closure = None, False
    for w in gd._walk(fn.body, skip_func_literals=False):
        if w.type != "assignment_statement" or not any(
                c.type == "identifier" and gd._t(c) == var for c in gd._named(w.child_by_field_name("left"))):
            continue
        a, lit_w = w.parent, None
        while a is not None and a != fn.body:
            if a.type == "func_literal":
                lit_w = a
                break
            a = a.parent
        if lit_w is not None and not gd._contains(lit_w, node):
            by_closure = True
            continue
        if w.start_byte < node.end_byte:
            continue
        a = node.parent
        while a is not None and a != fn.body and a.type != "func_literal":
            if a.type == "for_statement" and gd._contains(a, w) and a.child_by_field_name("body") is not None:
                b = a.child_by_field_name("body").start_byte
                boundary = b if boundary is None else min(boundary, b)
            a = a.parent
    return boundary, by_closure


class _Len:
    """Constraints on len(var): lower bounds and excluded values (`!=`)."""

    def __init__(self):
        self.lows: list[int] = []
        self.nes: set[int] = set()
        self.used: list[str] = []

    def add(self, op: str, n: int, text: str) -> None:
        self.used.append(text)
        if op in (">", ">=", "=="):
            self.lows.append({">": n + 1, ">=": n, "==": n}[op])
        elif op == "!=":
            self.nes.add(n)

    def bound(self, floor: int) -> int:
        lo = max([floor, *self.lows])
        while lo in self.nes:
            lo += 1
        return lo


BUG_EXPLAIN = {
    "ignored-error": "A function of this module declares an `error` result and the caller discards it: a "
                     "failure would go unnoticed.",
    "overwritten-error": "An error value is replaced before being checked: the first failure is lost.",
    "unchecked-split-index": "An element of a split result is read by constant index without a length check: "
                             "an input with too few separators makes the program panic (index out of range).",
    "nil-before-err-check": "A returned value is checked for nil and the loop/function exits before the returned "
                            "error is examined: when the callee returns (nil, err), the error is silently lost.",
    "unchecked-submatch-index": "An element of a regexp submatch result is read by constant index without checking "
                                "that the input matched: FindStringSubmatch returns nil on no match and the program "
                                "panics (index out of range).",
}


def _next_stmt(n):
    nxt = n.next_named_sibling
    while nxt is not None and nxt.type == "comment":
        nxt = nxt.next_named_sibling
    return nxt


def _in_closure(n, body) -> bool:
    cur = n.parent
    while cur is not None and cur != body:
        if cur.type == "func_literal":
            return True
        cur = cur.parent
    return False


def _mentions(node, name: str) -> bool:
    return any(n.type == "identifier" and gd._t(n) == name for n in gd._walk(node))


def _reads_same_err(later, s1, s2, body) -> bool:
    """The later `err` is not a fresh declaration/assignment (it reads the value produced at s1)."""
    p = later.parent
    if p is not None and p.type == "expression_list" and p.parent is not None and \
            p.parent.type in ("short_var_declaration", "assignment_statement") and \
            p.parent.child_by_field_name("left") == p:
        return False
    return True


@dataclass
class DetectionReport:
    """What one detection run looked at: lets storage explain why a stored candidate is no longer produced."""
    candidates: list[BugCandidate]
    files: set[str]                                          # indexed .go files (scope)
    skipped: list[str]                                       # symlinks / oversized files
    parse_errors: list[str]                                  # parsed with errors: absence there proves nothing
    suppressed: list[tuple[BugCandidate, dict]] = field(default_factory=list)   # (site, proof) proven safe


def detect_go_report(root: str | Path, include_tests: bool = False) -> DetectionReport:
    d = _Detector(Path(root), include_tests=include_tests)
    for key in sorted(d.ix.functions):
        d.ignored_errors(key)
        d.overwritten_errors(key)
        d.split_indexes(key)
        d.submatch_indexes(key)
        d.nil_before_err(key)
    return DetectionReport(sorted(d.out, key=lambda c: (c.file, c.line, c.category)), set(d.ix.files),
                           list(d.ix.skipped), list(d.ix.parse_errors), list(zip(d.suppressed, d.proofs)))


def detect_go_bugs(root: str | Path, include_tests: bool = False) -> list[BugCandidate]:
    """Bug candidates for the `.go` files under root, sorted by (file, line, category). Static only."""
    return detect_go_report(root, include_tests).candidates
