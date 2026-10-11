"""Per-function facts extracted from the syntax tree: state writes, external calls, guard conditions.

Name-based and intra-procedural: a write through an internal helper call or a storage pointer is not seen.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .parser import FunctionInfo, Project, base_identifier, call_args, callee_name, line, text, unwrap, walk

LOWLEVEL = {"call", "delegatecall", "staticcall", "send"}


@dataclass
class Write:
    var: str
    node: object
    start: int
    line: int


@dataclass
class ExtCall:
    kind: str           # lowlevel | highlevel | transfer
    method: str         # call | delegatecall | staticcall | send | transfer | <interface method>
    node: object        # the outermost call_expression
    start: int
    end: int
    line: int
    has_value: bool
    target: str         # base identifier of the receiver ('' if unknown)


class FunctionFacts:
    def __init__(self, fn: FunctionInfo, project: Project):
        self.fn = fn
        self.project = project
        shadow = set(fn.params) | fn.locals
        self.state = {n: v for n, v in project.state_vars(fn.contract).items() if n not in shadow}
        self.writes: list[Write] = []
        self.calls: list[ExtCall] = []
        self.conditions: list = []          # guard expressions (require/assert args, if/while conditions)
        if fn.body is not None:
            self._scan()

    # ------------------------------------------------------------ extraction
    def _var_type(self, name: str) -> str:
        if name in self.state:
            return self.state[name]["type"]
        fn = self.fn
        for n in walk(fn.node):
            if n.type in ("parameter", "variable_declaration"):
                ids = [x for x in n.named_children if x.type == "identifier"]
                if ids and text(ids[-1]) == name:
                    t = next((x for x in n.named_children if x.type == "type_name"), None)
                    return text(t)
        return ""

    def _is_contract_typed(self, receiver) -> bool:
        receiver = unwrap(receiver)
        known = self.project.type_names()
        if receiver.type == "call_expression":                  # IERC20(token).transfer(...)
            name = text(unwrap(receiver.named_children[0]))
            return name in known or bool(re.match(r"^I[A-Z]\w*$", name))
        if receiver.type == "identifier":
            t = self._var_type(text(receiver)).strip()
            return t in known or bool(re.match(r"^I[A-Z]\w*$", t))
        return False

    def _classify_call(self, call):
        callee = unwrap(call.named_children[0]) if call.named_child_count else None
        has_value = False
        if callee is not None and callee.type == "struct_expression":       # x.call{value: v}(...)
            has_value = any(text(f).replace(" ", "").startswith("value:") for f in callee.named_children
                            if f.type == "struct_field_assignment")
            callee = unwrap(callee.named_children[0])
        elif callee is not None and callee.type == "call_expression":       # legacy x.call.value(v)(...)
            inner = unwrap(callee.named_children[0])
            if inner is not None and inner.type == "member_expression" and text(inner.named_children[-1]) in ("value", "gas"):
                has_value = text(inner.named_children[-1]) == "value"
                callee = unwrap(inner.named_children[0])
        if callee is None or callee.type != "member_expression":
            return None
        method = text(callee.named_children[-1])
        receiver = callee.named_children[0]
        target = base_identifier(receiver)
        if method in LOWLEVEL:
            return ExtCall("lowlevel", method, call, call.start_byte, call.end_byte, line(call),
                           has_value or method == "send", target)
        if method == "transfer" and len(call_args(call)) == 1 and not self._is_contract_typed(receiver):
            return ExtCall("transfer", method, call, call.start_byte, call.end_byte, line(call), True, target)
        if method not in ("value", "gas") and self._is_contract_typed(receiver):
            return ExtCall("highlevel", method, call, call.start_byte, call.end_byte, line(call), has_value, target)
        return None

    def _add_write(self, lhs, node):
        name = base_identifier(lhs)
        if name in self.state and not self.state[name]["constant"]:
            self.writes.append(Write(name, node, node.start_byte, line(node)))

    def _scan(self):
        for n in walk(self.fn.body):
            t = n.type
            if t in ("assignment_expression", "augmented_assignment_expression"):
                lhs = n.named_children[0]
                if unwrap(lhs).type == "tuple_expression":
                    for el in unwrap(lhs).named_children:
                        self._add_write(el, n)
                else:
                    self._add_write(lhs, n)
            elif t == "update_expression":
                self._add_write(n.named_children[0], n)
            elif t == "unary_expression" and n.children and n.children[0].type == "delete":
                self._add_write(n.named_children[-1], n)
            elif t == "call_expression":
                name = callee_name(n)
                if name in ("require", "assert") and unwrap(n.named_children[0]).type == "identifier":
                    args = call_args(n)
                    if args:
                        self.conditions.append(args[0])
                else:
                    c = self._classify_call(n)
                    if c is not None:
                        self.calls.append(c)
            elif t in ("if_statement", "while_statement"):
                cond = next((c for c in n.named_children if c.type == "expression"), None)
                if cond is not None:
                    self.conditions.append(cond)

    # ------------------------------------------------------------ queries
    def state_refs_before(self, end_byte: int) -> set[str]:
        out = set()
        for n in walk(self.fn.body):
            if n.start_byte >= end_byte:
                continue
            if n.type == "identifier" and text(n) in self.state:
                out.add(text(n))
        return out

    def body_text(self) -> str:
        return text(self.fn.body)


# ---------------------------------------------------------------- access-control recognition
AC_MODIFIER_RE = re.compile(
    r"^(only[A-Z_]\w*|onlyRole|auth|requiresAuth|restricted|isAuthorized|ownerOnly|adminOnly|onlyOwnerOrAdmin)$")
_SENDER = r"(?:msg\.sender|_msgSender\(\s*\))"
_AC_COND_RES = [
    re.compile(_SENDER + r"\s*[!=]="),
    re.compile(r"[!=]=\s*" + _SENDER),
    re.compile(r"\b(hasRole|isOwner|isAdmin|_isAuthorized|isAuthorized|canCall|isOperator)\s*\("),
    re.compile(r"\b\w*(admin|owner|auth|operator|minter|role|whitelist|allowed|guardian|governor|keeper)\w*\s*\[\s*"
               + _SENDER + r"\s*\]", re.I),
]
_AC_CALL_RE = re.compile(r"\b(_checkOwner|_checkRole|_onlyOwner|_requireOwner|_authorizeUpgrade|requireAuth|"
                         r"_requireCallerIsOwner|_checkAuth|_auth)\s*\(")
_SIG_RE = re.compile(r"\becrecover\s*\(|\.recover\s*\(|\bisValidSignatureNow\s*\(")


_EOA_CHECK_RE = re.compile(r"tx\.origin\s*[!=]=\s*" + _SENDER + "|" + _SENDER + r"\s*[!=]=\s*tx\.origin")
_TX_ORIGIN_AUTH_RE = re.compile(r"tx\.origin\s*[!=]=|[!=]=\s*tx\.origin|\[\s*tx\.origin\s*\]")


def condition_is_sender_check(cond) -> bool:
    """Caller authorization in a condition. `tx.origin == msg.sender` (EOA check) is not authorization;
    tx.origin-based checks count as (weak) authorization because SOL-TX-ORIGIN reports them separately."""
    s = _EOA_CHECK_RE.sub("", text(cond))
    return any(r.search(s) for r in _AC_COND_RES) or bool(_TX_ORIGIN_AUTH_RE.search(s))


def access_control(facts: FunctionFacts) -> str:
    """Return a short description of the access control found, or '' if none was recognised."""
    fn, project = facts.fn, facts.project
    for m in fn.modifiers:
        mod = project.modifier(fn.contract, m)
        if mod is not None and mod.body is not None:      # body in scan path: judge the body, not the name
            mf = FunctionFacts(mod, project)
            if any(condition_is_sender_check(c) for c in mf.conditions) or _AC_CALL_RE.search(mf.body_text()):
                return f"modifier {m} (body checks the caller)"
        elif AC_MODIFIER_RE.match(m):
            return f"modifier {m} (name-based, definition not in scan path)"
    for c in facts.conditions:
        if condition_is_sender_check(c):
            return f"guard `{text(c)[:80]}` (line {line(c)})"
    body = facts.body_text()
    m = _AC_CALL_RE.search(body)
    if m:
        return f"call {m.group(1)}() (name-based)"
    m = _SIG_RE.search(body)
    if m:
        return "signature verification (ecrecover/recover)"
    return ""


REENTRANCY_GUARD_RE = re.compile(r"(nonReentrant|noReentran\w*|reentrancyGuard|lock|mutex|guarded)", re.I)
INITIALIZER_MODIFIERS = {"initializer", "reinitializer", "onlyInitializing"}


# ---------------------------------------------------------------- authority variables (role derived from use)
_SENDER_EXPR_RE = re.compile(r"^(msg\.sender|_msgSender\(\))$")


def _authority_side(node, state: dict) -> str:
    """State variable on the other side of a msg.sender comparison: `owner`, `address(owner)`."""
    name = base_identifier(node)
    u = unwrap(node)
    if u.type not in ("identifier", "call_expression", "payable_conversion_expression", "type_cast_expression"):
        return ""
    if name in state and not state[name]["constant"] and "mapping" not in state[name]["type"]:
        return name
    return ""


def authority_vars(project: Project, contract) -> dict:
    """State variables whose privileged role is visible from their USE in the contract (or its bases):
    - compared for equality with msg.sender in a require/assert, or in an if condition (`if (msg.sender != x)
      revert`): the variable designates who is authorized;
    - used as a delegatecall target: whoever sets it runs code in this contract's storage.
    Returns {var: reason}. Name-based resolution, constants/immutables excluded (cannot be re-set)."""
    cache = project.__dict__.setdefault("_authority_cache", {})
    if contract.name in cache:
        return cache[contract.name]
    state = project.state_vars(contract)
    out: dict[str, str] = {}
    for c in project.linearized(contract):
        for fn in c.functions + list(c.modifiers.values()):
            if fn.body is None:
                continue
            shadow = set(fn.params) | fn.locals
            fstate = {k: v for k, v in state.items() if k not in shadow}
            for n in walk(fn.body):
                conds, ops = [], ()
                if n.type == "call_expression" and callee_name(n) in ("require", "assert") \
                        and unwrap(n.named_children[0]).type == "identifier":
                    conds, ops = call_args(n)[:1], ("==",)
                elif n.type == "if_statement":
                    conds = [x for x in n.named_children if x.type == "expression"][:1]
                    ops = ("==", "!=")
                for cond in conds:
                    for b in walk(cond):
                        if b.type != "binary_expression" or b.named_child_count != 2:
                            continue
                        op = next((text(x) for x in b.children if not x.is_named), "")
                        if op not in ops:
                            continue
                        lhs, rhs = b.named_children
                        for me, other in ((lhs, rhs), (rhs, lhs)):
                            if _SENDER_EXPR_RE.match(text(me).replace(" ", "")):
                                v = _authority_side(other, fstate)
                                if v:
                                    out.setdefault(v, f"compared with msg.sender in {c.name}.{fn.name} "
                                                      f"(line {line(b)})")
            if fn.kind != "modifier":
                for call in FunctionFacts(fn, project).calls:
                    if call.method == "delegatecall" and call.target in fstate \
                            and not fstate[call.target]["constant"]:
                        out.setdefault(call.target, f"delegatecall target in {c.name}.{fn.name} (line {call.line})")
    cache[contract.name] = out
    return out
