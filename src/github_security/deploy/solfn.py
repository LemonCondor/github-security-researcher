"""Deterministic per-function facts for the delta engine, built on contracts/parser.py (tree-sitter).

No LLM. Comments and whitespace are stripped before any comparison, so metadata/formatting/comment-only
and pure-reorder diffs are not seen as functional changes. Every extracted fact is a syntactic construct
(a modifier invocation node, a require/assert call, a numeric comparison, an arithmetic assignment, a value
transfer), never a name heuristic.
"""
from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..contracts.parser import FunctionInfo, base_identifier, callee_name, parse_file, text, unwrap, walk
from .models import (DIRECT_USER_FUNDS_PATH, FUNDS_UNKNOWN, INDIRECT_USER_FUNDS_PATH,
                     NO_IDENTIFIED_FUNDS_PATH)

_CALLER_IDENT = ("msg.sender", "_msgsender", "tx.origin")
_ROLE_CALLS = ("hasrole", "checkrole", "onlyrole", "_checkrole", "require_auth", "requireauth")
_TRANSFER_CALLS = ("transfer", "transferfrom", "safetransfer", "safetransferfrom", "send", "sendvalue")
_CONVERSION_HINT = re.compile(r"\b(muldiv|mulwad|divwad|convert[A-Za-z]*|toShares|toAssets|to_assets|to_shares)\b",
                              re.I)
_NUM_CMP = re.compile(r"(<=|>=|<|>|==|!=)\s*(0x[0-9a-fA-F]+|\d[\d_]*)")
_WS = re.compile(r"\s+")
_LINE_COMMENT = re.compile(r"//[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


@dataclass
class FnFacts:
    signature: str
    visibility: str
    changes_state: bool
    access_modifiers: tuple          # modifier invocations (structural access gates)
    has_sender_check: bool           # require/if referencing msg.sender / role call in the body
    guards: tuple                    # normalized require/assert/revert-if conditions
    numeric_comparisons: tuple       # (operator, literal) pairs
    arithmetic: tuple                # normalized assignment/arith statements
    has_value_transfer: bool
    norm_body: str                   # comment/whitespace-stripped body (the functional fingerprint)
    internal_calls: tuple = ()       # bare-identifier callee names (candidate intra-file calls)


def _strip(src: str) -> str:
    src = _BLOCK_COMMENT.sub(" ", src)
    src = _LINE_COMMENT.sub(" ", src)
    return _WS.sub(" ", src).strip()


def parse_source(src: str, display: str = "mem.sol"):
    """Parse Solidity source text (written to a temp file; parser reads paths)."""
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "mem.sol"
        p.write_bytes(src.encode())
        return parse_file(p, display=display)


def _body_text(fn: FunctionInfo) -> str:
    return text(fn.body) if fn.body is not None else ""


def _guards_and_calls(fn: FunctionInfo):
    guards, nums, arith = [], [], []
    internal = []
    has_sender, has_transfer = False, False
    if fn.body is None:
        return guards, nums, arith, has_sender, has_transfer, internal
    btext = _strip(_body_text(fn))
    for op, lit in _NUM_CMP.findall(btext):
        nums.append((op, lit.replace("_", "")))
    for node in walk(fn.body):
        t = node.type
        if t == "call_expression":
            name = (callee_name(node) or "").lower()
            callee = unwrap(node.named_children[0]) if node.named_child_count else None
            if callee is not None and callee.type == "identifier":
                cn = text(callee)
                if cn not in ("require", "assert", "revert"):
                    internal.append(cn)   # candidate intra-file call; resolved later against the file
            if name in ("require", "assert"):
                guards.append(_strip(text(node)))
                if any(s in text(node).lower().replace(" ", "") for s in ("msg.sender", "tx.origin")):
                    has_sender = True
            if name in _ROLE_CALLS:
                has_sender = True
            short = name.split(".")[-1]
            if short in _TRANSFER_CALLS:
                has_transfer = True
            if "{value:" in _strip(text(node)).replace(" ", "") or ".call{value" in text(node).replace(" ", ""):
                has_transfer = True
        elif t in ("revert_statement",):
            guards.append(_strip(text(node)))
        elif t == "if_statement" and "revert" in text(node).lower():
            guards.append(_strip(text(node)))
            if "msg.sender" in text(node).replace(" ", "").lower():
                has_sender = True
        elif t in ("assignment_expression", "augmented_assignment_expression",
                   "variable_declaration_statement"):
            s = _strip(text(node))
            if any(opx in s for opx in ("+=", "-=", "*=", "/=")) or re.search(r"[^=<>!]=[^=]", s) and \
               (re.search(r"[+\-*/]", s) or _CONVERSION_HINT.search(s)):
                arith.append(s)
    return guards, nums, arith, has_sender, has_transfer, internal


def function_facts(sf) -> dict:
    """Map 'name(params)' -> FnFacts for every function (not modifiers) in the file."""
    out: dict[str, FnFacts] = {}
    for c in sf.contracts:
        for fn in c.functions:
            if fn.kind not in ("function", "fallback", "receive", "constructor"):
                continue
            sig = f"{fn.name}({','.join(fn.params)})"
            guards, nums, arith, sender, transfer, internal = _guards_and_calls(fn)
            out[sig] = FnFacts(
                signature=sig, visibility=fn.visibility or "", changes_state=fn.changes_state,
                access_modifiers=tuple(sorted(fn.modifiers)), has_sender_check=sender,
                guards=tuple(sorted(guards)), numeric_comparisons=tuple(sorted(nums)),
                arithmetic=tuple(sorted(arith)), has_value_transfer=transfer,
                norm_body=_strip(_body_text(fn)), internal_calls=tuple(internal))
    return out


def _name_of(sig: str) -> str:
    return sig.split("(", 1)[0]


def funds_proximity(sig: str, facts: dict) -> str:
    """Conservative, static, intra-file funds-path classification for one deployed function.

    DIRECT when a value transfer appears in the function itself. Otherwise a bounded (depth <= 3) walk of
    UNAMBIGUOUS, resolved intra-file calls looks for a recognised financial sink (a value transfer in a
    reached function) => INDIRECT. No sink reached: NO_IDENTIFIED for a view/pure function (it cannot move
    funds), UNKNOWN otherwise (we never assert "no path" for a state-changing function, nor guess from names).
    External calls, interfaces, builtins and ambiguous dispatch are not followed (treated as unresolved).
    """
    f = facts.get(sig)
    if f is None:
        return FUNDS_UNKNOWN
    if f.has_value_transfer:
        return DIRECT_USER_FUNDS_PATH
    by_name: dict = {}
    for s in facts:
        by_name.setdefault(_name_of(s), []).append(s)
    MAX_DEPTH = 3
    seen = {sig}
    frontier = [(sig, 0)]
    while frontier:
        cur, depth = frontier.pop()
        cf = facts.get(cur)
        if cf is None or depth >= MAX_DEPTH:
            continue
        for callee in cf.internal_calls:
            defs = by_name.get(callee, [])
            if len(defs) != 1:
                continue                       # 0 = external/builtin (unresolved); >1 = ambiguous: do not follow
            tgt = defs[0]
            tf = facts.get(tgt)
            if tf is not None and tf.has_value_transfer:
                return INDIRECT_USER_FUNDS_PATH   # complete resolved chain to a recognised sink
            if tgt not in seen:                # cycle guard
                seen.add(tgt)
                frontier.append((tgt, depth + 1))
    return NO_IDENTIFIED_FUNDS_PATH if not f.changes_state else FUNDS_UNKNOWN
