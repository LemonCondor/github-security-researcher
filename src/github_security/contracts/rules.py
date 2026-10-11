"""Detection rules of contracts.solidity/2. Each rule yields RuleHit objects; engine.py turns them into
EngineFinding. A hit with `suppressed` set carries deterministic or name-based negative evidence and is only
reported when the caller asks for suppressed hits (status FALSE_POSITIVE)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .analysis import INITIALIZER_MODIFIERS, REENTRANCY_GUARD_RE, FunctionFacts, access_control, authority_vars
from .parser import SourceFile, base_identifier, call_args, callee_name, line, text, unwrap, walk


@dataclass
class RuleHit:
    rule: str
    line: int
    contract: str
    function: str
    description: str
    evidence_lines: list[int]
    status: str = "CANDIDATE"
    severity: str = "medium"
    confidence: float = 0.5
    suppressed: str = ""          # reason, when negative evidence was found
    suppressed_strength: str = "moderate"
    extra: dict = field(default_factory=dict)


RULES = {
    # rule id: (category, default severity, short title)
    "SOL-REENTRANCY": ("reentrancy", "high", "state written after an external call (CEI violated)"),
    "SOL-ACCESS-CONTROL": ("access-control", "high", "sensitive function without recognised access control"),
    "SOL-TX-ORIGIN": ("tx-origin-auth", "medium", "authorization based on tx.origin"),
    "SOL-UNPROTECTED-INIT": ("unprotected-initializer", "high", "initializer callable by anyone, more than once"),
    "SOL-UNCHECKED-CALL": ("unchecked-low-level-call", "medium", "low-level call return value ignored"),
    "SOL-DELEGATECALL-PARAM": ("controlled-delegatecall", "high", "delegatecall to a caller-supplied address"),
    "SOL-UNCHECKED-ARITH": ("unchecked-arithmetic", "low", "arithmetic inside unchecked{}"),
    "SOL-LEGACY-ARITH": ("legacy-arithmetic", "medium", "raw arithmetic on state under pragma <0.8 (no built-in overflow check)"),
}


# ------------------------------------------------------------------ reentrancy
def rule_reentrancy(f: FunctionFacts):
    fn = f.fn
    if not (fn.is_entry and fn.changes_state) or fn.kind in ("receive", "fallback"):
        return
    for call in f.calls:
        if call.kind == "transfer" or (call.kind == "lowlevel" and call.method in ("send", "staticcall")):
            continue        # 2300-gas stipend / no state change possible: out of scope (documented)
        before = f.state_refs_before(call.end)
        late = [w for w in f.writes if w.start > call.end and w.var in before]
        if not late:
            continue
        w = late[0]
        strong = call.kind == "lowlevel" and call.method == "call"
        hit = RuleHit(
            "SOL-REENTRANCY", call.line, fn.contract.name, fn.name,
            f"`{call.method}` external call at line {call.line} precedes a write to state `{w.var}` "
            f"(line {w.line}) that was read before the call: checks-effects-interactions order is violated.",
            [call.line, w.line],
            status="CANDIDATE" if strong else "NEEDS_REVIEW",
            severity="high" if strong and call.has_value else "medium",
            confidence=0.6 if strong and call.has_value else (0.45 if strong else 0.3),
            extra={"call_kind": call.kind, "state_var": w.var})
        guard = next((m for m in fn.modifiers if REENTRANCY_GUARD_RE.search(m)), "")
        if guard:
            hit.suppressed = f"reentrancy guard modifier `{guard}` (name-based, body not verified)"
        yield hit
        return      # one hit per function


# ------------------------------------------------------------------ access control
SENSITIVE_NAME_RE = re.compile(
    r"^(mint\w*|_?setOwner|transferOwnership|renounceOwnership|changeOwner|setAdmin|changeAdmin|upgradeTo|"
    r"upgradeToAndCall|setImplementation|withdrawAll|emergencyWithdraw|sweep\w*|rescue\w*|kill|destroy|pause|"
    r"unpause|setOracle|setFee\w*|setTreasury)$")
PRIV_VAR_RE = re.compile(
    r"^_?(is)?(owner|admin|pendingOwner|pendingAdmin|governance|governor|implementation|operator|minter|guardian|"
    r"treasury|oracle|paused|feeRecipient|signer|controller)s?$", re.I)
INIT_NAME_RE = re.compile(r"^_{0,2}(initiali[sz]e\w*|init(?:[A-Z_0-9]\w*)?)$")


def _sensitivity(f: FunctionFacts) -> str:
    fn = f.fn
    for n in walk(fn.body):
        if n.type == "call_expression" and callee_name(n) in ("selfdestruct", "suicide") \
                and unwrap(n.named_children[0]).type == "identifier":
            return f"calls {callee_name(n)} (line {line(n)})"
    if SENSITIVE_NAME_RE.match(fn.name):
        if fn.name.lower().startswith("mint") and fn.mutability == "payable":
            return ""       # paid public mint (sale) is public by design
        return f"privileged function name `{fn.name}`"
    priv = [w for w in f.writes if PRIV_VAR_RE.match(w.var)]
    if priv:
        return f"writes privileged state `{priv[0].var}` (line {priv[0].line})"
    for c in f.calls:
        if c.kind in ("lowlevel", "transfer") and "address(this).balance" in text(c.node).replace(" ", ""):
            return f"sends the whole contract balance (line {c.line})"
    return ""


_CONTROLLED_RHS_RE = re.compile(r"^(msg\.sender|_msgSender\(\)|tx\.origin)$")


def _authority_write(f: FunctionFacts):
    """Direct write to a state variable whose privileged role is derived from its use elsewhere (compared with
    msg.sender, or a delegatecall target). Returns (why, caller_controlled) or None."""
    auth = authority_vars(f.project, f.fn.contract)
    for w in f.writes:
        if w.var not in auth or w.node.type != "assignment_expression":
            continue
        if unwrap(w.node.named_children[0]).type != "identifier":
            continue
        rhs = unwrap(w.node.named_children[-1])
        src = base_identifier(rhs)
        controlled = bool(_CONTROLLED_RHS_RE.match(text(rhs).replace(" ", ""))) or src in f.fn.params
        return f"writes `{w.var}` (line {w.line}), a variable {auth[w.var]}", controlled
    return None


def rule_access_control(f: FunctionFacts):
    fn = f.fn
    if fn.kind not in ("function", "fallback", "receive") or not fn.is_entry or not fn.changes_state \
            or fn.body is None:
        return
    if INIT_NAME_RE.match(fn.name):
        return          # handled by SOL-UNPROTECTED-INIT
    why, status = _sensitivity(f), "CANDIDATE"
    if not why:
        aw = _authority_write(f)
        if aw is None:
            return
        why, controlled = aw
        status = "CANDIDATE" if controlled else "NEEDS_REVIEW"
        if fn.kind == "function" and fn.name[:1].isupper():
            why += " (capitalised name: possibly a misnamed pre-0.4.22 constructor, SWC-118)"
    hit = RuleHit("SOL-ACCESS-CONTROL", fn.line, fn.contract.name, fn.name,
                  f"`{fn.name}` is externally callable and {why}, but no access control was recognised "
                  f"(no only*/role modifier, no msg.sender comparison, no hasRole/_checkOwner).",
                  [fn.line], status=status, severity="high", confidence=0.55 if status == "CANDIDATE" else 0.35,
                  extra={"sensitivity": why})
    ac = access_control(f)
    if ac:
        hit.suppressed = f"access control: {ac}"
        hit.suppressed_strength = "strong" if "body checks" in ac or ac.startswith("guard") else "moderate"
    yield hit


# ------------------------------------------------------------------ tx.origin
def rule_tx_origin(f: FunctionFacts):
    fn = f.fn
    if fn.body is None:
        return
    for cond in f.conditions:
        for n in walk(cond):
            if n.type == "member_expression" and text(n).replace(" ", "") == "tx.origin":
                cmp = n.parent
                while cmp is not None and cmp.type == "expression":
                    cmp = cmp.parent
                if cmp is not None and cmp.type == "binary_expression":
                    other = [c for c in cmp.named_children if c.start_byte != n.start_byte
                             and not (c.start_byte <= n.start_byte < c.end_byte)]
                    if other and re.fullmatch(r"(msg\.sender|_msgSender\(\))", text(other[0]).replace(" ", "")):
                        continue        # tx.origin == msg.sender: EOA check, not authorization
                yield RuleHit("SOL-TX-ORIGIN", line(n), fn.contract.name, fn.name,
                              f"`tx.origin` used in an authorization condition (`{text(cond)[:80]}`): a contract "
                              f"called by the legitimate user can act on their behalf (phishing).",
                              [line(n)], severity="medium", confidence=0.7)
                return


# ------------------------------------------------------------------ unprotected initializer
def rule_unprotected_init(f: FunctionFacts):
    fn = f.fn
    if fn.kind != "function" or not fn.is_entry or fn.body is None or not INIT_NAME_RE.match(fn.name):
        return
    if not f.writes:
        return
    hit = RuleHit("SOL-UNPROTECTED-INIT", fn.line, fn.contract.name, fn.name,
                  f"`{fn.name}` is {fn.visibility or 'public (default)'} and writes state "
                  f"({', '.join(sorted({w.var for w in f.writes}))}) with no `initializer` modifier and no one-time "
                  f"guard: anyone can (re-)initialize it, e.g. take ownership.",
                  [fn.line] + [w.line for w in f.writes[:3]], severity="high", confidence=0.65)
    init_mod = [m for m in fn.modifiers if m in INITIALIZER_MODIFIERS]
    written = {w.var for w in f.writes}
    guard = next((c for c in f.conditions
                  if any(n.type == "identifier" and text(n) in written for n in walk(c))), None)
    ac = access_control(f)
    if init_mod:
        hit.suppressed = f"modifier `{init_mod[0]}` (name-based, OpenZeppelin semantics assumed)"
    elif guard is not None:
        hit.suppressed, hit.suppressed_strength = (
            f"one-time guard `{text(guard)[:80]}` (line {line(guard)}) on state written by the function", "strong")
    elif ac:
        hit.suppressed = f"access control: {ac}"
    yield hit


# ------------------------------------------------------------------ unchecked low-level call
def _result_var(call):
    """Return ('discarded', None) | ('used', None) | ('var', name)."""
    node = call
    while node.parent is not None and node.parent.type in ("expression", "parenthesized_expression"):
        node = node.parent
    p = node.parent
    if p is None:
        return "used", None
    if p.type == "expression_statement":
        return "discarded", None
    if p.type == "variable_declaration_statement":
        first = p.named_children[0]
        if first.type == "variable_declaration_tuple":
            kids = [c for c in first.children if c.type not in ("(",)]
            if not kids or kids[0].type == ",":
                return "discarded", None
            ids = [x for x in kids[0].named_children if x.type == "identifier"]
            return ("var", text(ids[-1])) if ids else ("used", None)
        if first.type == "variable_declaration":
            ids = [x for x in first.named_children if x.type == "identifier"]
            return ("var", text(ids[-1])) if ids else ("used", None)
    if p.type == "assignment_expression" and p.named_children[-1].start_byte <= call.start_byte:
        lhs = unwrap(p.named_children[0])
        if lhs.type == "tuple_expression":
            kids = [c for c in lhs.children if c.type != "("]
            if not kids or kids[0].type == ",":
                return "discarded", None
            return "var", base_identifier(kids[0])
        return "var", base_identifier(lhs)
    return "used", None


def _var_checked_after(f: FunctionFacts, name: str, after: int) -> bool:
    for n in walk(f.fn.body):
        if n.type == "identifier" and text(n) == name and n.start_byte > after:
            anc = n.parent
            while anc is not None and anc.type not in ("expression_statement", "if_statement", "return_statement",
                                                       "while_statement", "emit_statement",
                                                       "variable_declaration_statement", "revert_statement"):
                anc = anc.parent
            if anc is None or anc.type == "emit_statement":
                continue
            if anc.type == "expression_statement":
                e = unwrap(anc.named_children[0])
                if e.type == "assignment_expression" and base_identifier(e.named_children[0]) == name:
                    continue        # overwritten, not checked
            return True
    return False


def rule_unchecked_call(f: FunctionFacts):
    fn = f.fn
    for c in f.calls:
        if c.kind != "lowlevel":
            continue
        state, var = _result_var(c.node)
        hit = RuleHit("SOL-UNCHECKED-CALL", c.line, fn.contract.name, fn.name,
                      f"return value of `.{c.method}` is not checked: a failed call is silently ignored and "
                      f"execution continues.", [c.line],
                      severity="high" if c.method == "delegatecall" else "medium", confidence=0.7,
                      extra={"method": c.method})
        if state == "used":
            hit.suppressed, hit.suppressed_strength = "result consumed directly (require/if/return/argument)", "strong"
        elif state == "var":
            if var in fn.returns:
                hit.suppressed, hit.suppressed_strength = f"success flag `{var}` is a named return value", "strong"
            elif _var_checked_after(f, var, c.end):
                hit.suppressed, hit.suppressed_strength = f"success flag `{var}` is checked after the call", "strong"
            else:
                hit.description = (f"success flag `{var}` of `.{c.method}` is never checked: a failed call is "
                                   f"silently ignored.")
        yield hit


_YUL_CALLS = {"call", "callcode", "delegatecall", "staticcall"}


def _yul_builtin(n) -> str:
    b = n.named_children[0] if n.named_child_count else None
    return text(b).strip() if b is not None and b.type == "yul_evm_builtin" else ""


def _yul_used_after(f: FunctionFacts, name: str, after: int) -> bool:
    """`name` (Yul or Solidity identifier) is read after byte `after` (not merely overwritten)."""
    for n in walk(f.fn.body):
        if n.type != "identifier" or text(n) != name or n.start_byte <= after:
            continue
        anc = n.parent
        while anc is not None and anc.type in ("yul_identifier", "yul_path"):
            anc = anc.parent
        if anc is not None and anc.type == "yul_assignment" and anc.named_children \
                and anc.named_children[0].start_byte <= n.start_byte < anc.named_children[0].end_byte:
            continue                    # overwritten in assembly
        if anc is not None and anc.type == "assignment_expression" and base_identifier(anc.named_children[0]) == name \
                and n.start_byte < anc.named_children[0].end_byte:
            continue                    # overwritten in Solidity
        return True
    return False


def rule_unchecked_asm_call(f: FunctionFacts):
    """call/delegatecall/callcode/staticcall builtins inside `assembly {}` whose success word is ignored."""
    fn = f.fn
    if fn.body is None:
        return
    for n in walk(fn.body):
        if n.type != "yul_function_call" or _yul_builtin(n) not in _YUL_CALLS:
            continue
        method, p = _yul_builtin(n), n.parent
        status, why, var = "CANDIDATE", "", ""
        if p.type in ("yul_variable_declaration", "yul_assignment"):
            ids = [x for x in walk(p.named_children[0]) if x.type == "identifier"] if p.named_child_count else []
            var = text(ids[0]) if ids else ""
            if not var:
                continue
            if var in fn.returns:
                why = "named return value"
            elif _yul_used_after(f, var, n.end_byte):
                why = "checked after the call"
            if why:
                why = f"success word `{var}` is {why}"
        elif p.type == "yul_function_call" and _yul_builtin(p) == "pop":
            status = "NEEDS_REVIEW"
        elif p.type in ("assembly_statement", "yul_block"):
            pass                        # bare statement (not valid Yul for a value-returning builtin): discarded
        else:
            why = "result consumed directly (if/iszero/switch/argument)"
        desc = (f"success word `{var}` of assembly `{method}` is never read" if var else
                f"result of assembly `{method}` is explicitly discarded with pop()" if status == "NEEDS_REVIEW" else
                f"result of assembly `{method}` is discarded")
        hit = RuleHit("SOL-UNCHECKED-CALL", line(n), fn.contract.name, fn.name,
                      desc + ": a failed call is silently ignored and execution continues.", [line(n)],
                      status=status, severity="high" if method in ("delegatecall", "callcode") else "medium",
                      confidence=0.6 if status == "CANDIDATE" else 0.3, extra={"method": f"assembly:{method}"})
        if why:
            hit.suppressed, hit.suppressed_strength = why, "strong"
        yield hit


# ------------------------------------------------------------------ delegatecall to parameter
def rule_delegatecall_param(f: FunctionFacts):
    fn = f.fn
    if not fn.is_entry or fn.body is None:
        return
    for c in f.calls:
        if c.method != "delegatecall":
            continue
        tgt = c.target
        if tgt in fn.params or tgt == "msg":
            hit = RuleHit("SOL-DELEGATECALL-PARAM", c.line, fn.contract.name, fn.name,
                          f"`delegatecall` target `{tgt}` comes from the caller: arbitrary code runs in this "
                          f"contract's storage context (owner overwrite, selfdestruct, fund theft).",
                          [c.line], severity="high", confidence=0.7)
            ac = access_control(f)
            if ac:
                hit.suppressed = f"access control: {ac} (admin-controlled delegatecall by design)"
            yield hit


# ------------------------------------------------------------------ arithmetic
_ARITH_BIN = {"+", "-", "*", "**"}
_ARITH_AUG = {"+=", "-=", "*="}


def _op(n) -> str:
    ops = [c for c in n.children if not c.is_named]
    return text(ops[0]) if ops else ""


def _arith_ops(root, f: FunctionFacts):
    """Arithmetic operations under `root`, minus local loop-counter increments. Yields (node, op)."""
    for n in walk(root):
        if n.type == "binary_expression" and _op(n) in _ARITH_BIN:
            yield n, _op(n)
        elif n.type == "augmented_assignment_expression" and _op(n) in _ARITH_AUG:
            tgt = base_identifier(n.named_children[0])
            if tgt not in f.state and text(n.named_children[-1]).strip() == "1":
                continue
            yield n, _op(n)
        elif n.type == "update_expression":
            if base_identifier(n.named_children[0]) not in f.state:
                continue        # ++i on a local loop counter
            yield n, "++/--"


def _sub_is_guarded(n, f: FunctionFacts) -> bool:
    """`a - b` preceded by a condition comparing a and b (require(a >= b), if (b > a) revert ...)."""
    a, b = (text(x).replace(" ", "") for x in (n.named_children[0], n.named_children[-1]))
    for cond in f.conditions:
        if cond.start_byte >= n.start_byte:
            continue
        s = text(cond).replace(" ", "")
        if a in s and b in s and re.search(r"[<>]=?", s):
            return True
    return False


def rule_unchecked_arith(f: FunctionFacts):
    fn = f.fn
    if fn.body is None:
        return
    for blk in walk(fn.body):
        if blk.type != "block_statement" or not blk.children or blk.children[0].type != "unchecked":
            continue
        ops = []
        for n, op in _arith_ops(blk, f):
            if op == "-" and _sub_is_guarded(n, f):
                continue
            if op == "-=" and _sub_is_guarded_aug(n, f):
                continue
            ops.append((n, op))
        if not ops:
            continue
        touches_state = any(base_identifier(n.named_children[0]) in f.state for n, op in ops
                            if n.type != "binary_expression")
        yield RuleHit("SOL-UNCHECKED-ARITH", line(blk), fn.contract.name, fn.name,
                      f"{len(ops)} arithmetic operation(s) inside `unchecked {{}}` without a preceding bound check "
                      f"recognised: overflow/underflow wraps silently. Review that the bounds are proven elsewhere.",
                      sorted({line(n) for n, _ in ops})[:5], status="NEEDS_REVIEW",
                      severity="medium" if touches_state else "low", confidence=0.3)


def _sub_is_guarded_aug(n, f: FunctionFacts) -> bool:
    a, b = (text(x).replace(" ", "") for x in (n.named_children[0], n.named_children[-1]))
    for cond in f.conditions:
        if cond.start_byte < n.start_byte:
            s = text(cond).replace(" ", "")
            if a in s and b in s and re.search(r"[<>]=?", s):
                return True
    return False


def pragma_is_legacy(sf: SourceFile) -> bool:
    """True when every version accepted by the pragma is < 0.8.0 (built-in overflow checks absent)."""
    if not sf.pragma:
        return False
    upper = None
    for op, (ma, mi, pa) in sf.pragma:
        v = (ma, mi, pa)
        if op in ("=", ""):
            cand = v
        elif op == "^":
            cand = (ma, mi, 10 ** 6) if ma == 0 else (ma, 10 ** 6, 0)
        elif op == "~":
            cand = (ma, mi, 10 ** 6)
        elif op == "<":
            cand = (ma, mi, pa - 1) if pa > 0 else (ma, mi - 1, 10 ** 6)
        elif op == "<=":
            cand = v
        else:       # >= / > : no upper bound from this term
            continue
        upper = cand if upper is None else min(upper, cand)
    return upper is not None and upper < (0, 8, 0)


def rule_legacy_arith(f: FunctionFacts, legacy: bool):
    fn = f.fn
    if not legacy or fn.body is None or not fn.changes_state:
        return
    ops = []
    for w in f.writes:
        node = w.node
        if node.type == "augmented_assignment_expression" and _op(node) in _ARITH_AUG:
            if _op(node) == "-=" and _sub_is_guarded_aug(node, f):
                continue
            ops.append(node)
        elif node.type == "update_expression":
            ops.append(node)
        elif node.type == "assignment_expression":
            for n, op in _arith_ops(node.named_children[-1], f):
                if op == "-" and _sub_is_guarded(n, f):
                    continue
                ops.append(n)
                break
    if not ops:
        return
    uses_sm = any("SafeMath" in u for c in f.project.linearized(fn.contract) for u in c.usings)
    yield RuleHit("SOL-LEGACY-ARITH", line(ops[0]), fn.contract.name, fn.name,
                  f"pragma allows only <0.8.0 (no built-in overflow checks) and {len(ops)} raw arithmetic "
                  f"write(s) to state are not routed through SafeMath{' (SafeMath is imported but not used here)' if uses_sm else ''}.",
                  sorted({line(n) for n in ops})[:5], status="NEEDS_REVIEW", severity="medium", confidence=0.35)


FUNCTION_RULES = [rule_reentrancy, rule_access_control, rule_tx_origin, rule_unprotected_init,
                  rule_unchecked_call, rule_unchecked_asm_call, rule_delegatecall_param, rule_unchecked_arith]
