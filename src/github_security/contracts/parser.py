"""Syntax-only Solidity model built on tree-sitter-solidity (no solc, no compilation, no code execution).

What this gives the rules: per file -> pragma constraints, contracts (kind, bases, `using` directives, state
variables, functions, modifiers); per function -> visibility, mutability, modifier invocations, parameters,
locals, line span and the tree-sitter body node.

Limits (by construction, documented in coverage.py): no type checking, no name resolution beyond simple
identifiers, no imported files (only files inside the scanned path are known), inheritance resolved by name only
within the scanned path, overloads not distinguished.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..engines.contract import DependencyMissing

_PARSER = None
_PARSER_VERSION = ""


def get_parser():
    """Return (parser, grammar_version). Raises DependencyMissing if the grammar is not installed."""
    global _PARSER, _PARSER_VERSION
    if _PARSER is None:
        try:
            import warnings
            from importlib.metadata import version

            import tree_sitter
            import tree_sitter_solidity
        except ImportError as exc:  # pragma: no cover - exercised only when the extra is absent
            raise DependencyMissing(
                "tree-sitter-solidity is not installed (pip install tree-sitter tree-sitter-solidity)") from exc
        with warnings.catch_warnings():           # tree-sitter-solidity 1.2.x returns an int pointer
            warnings.simplefilter("ignore", DeprecationWarning)
            lang = tree_sitter.Language(tree_sitter_solidity.language())
        _PARSER = tree_sitter.Parser(lang)
        _PARSER_VERSION = f"tree-sitter {version('tree-sitter')} / tree-sitter-solidity {version('tree-sitter-solidity')}"
    return _PARSER, _PARSER_VERSION


# ---------------------------------------------------------------- small tree helpers
def text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def line(node) -> int:
    return node.start_point[0] + 1


def walk(node):
    """Pre-order traversal in source order."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def unwrap(node):
    """Strip `expression` / parenthesized wrappers."""
    while node is not None and node.type in ("expression", "parenthesized_expression") and node.named_child_count == 1:
        node = node.named_children[0]
    return node


def base_identifier(node) -> str:
    """Leftmost identifier of an lvalue / receiver: bal[a][b].x -> bal ; payable(x) -> x ; address(p) -> p."""
    node = unwrap(node)
    while node is not None:
        t = node.type
        if t == "identifier":
            return text(node)
        if t in ("array_access", "member_expression", "slice_access"):
            node = unwrap(node.named_children[0]) if node.named_child_count else None
        elif t == "unary_expression" and node.children and node.children[0].type == "delete":
            node = unwrap(node.named_children[-1])
        elif t in ("payable_conversion_expression", "type_cast_expression") or (
                t == "call_expression" and _is_type_conversion(node)):
            args = [c for c in node.named_children if c.type == "call_argument"]
            node = unwrap(args[0].named_children[0]) if args and args[0].named_child_count else None
        elif t in ("expression", "parenthesized_expression", "call_argument", "tuple_expression"):
            node = node.named_children[0] if node.named_child_count else None
        else:
            return ""
    return ""


_CONVERSIONS = {"address", "payable", "uint", "uint256", "uint160", "bytes32", "int256"}


def _is_type_conversion(call) -> bool:
    callee = unwrap(call.named_children[0]) if call.named_child_count else None
    if callee is None:
        return False
    if callee.type == "primitive_type" or (callee.type == "type_name"):
        return True
    return callee.type == "identifier" and text(callee) in _CONVERSIONS


def callee_name(call) -> str:
    callee = unwrap(call.named_children[0]) if call.named_child_count else None
    if callee is None:
        return ""
    if callee.type == "identifier":
        return text(callee)
    if callee.type == "member_expression":
        return text(callee.named_children[-1])
    return ""


def call_args(call) -> list:
    return [unwrap(c.named_children[0]) for c in call.named_children if c.type == "call_argument" and c.named_child_count]


# ---------------------------------------------------------------- model
@dataclass
class FunctionInfo:
    name: str
    kind: str                       # function | constructor | fallback | receive | modifier
    visibility: str                 # public | external | internal | private ('' = default)
    mutability: str                 # view | pure | payable | ''
    modifiers: list[str]
    params: list[str]               # inputs + named return parameters
    locals: set[str]
    line: int
    end_line: int
    body: object                    # tree-sitter node or None (abstract / interface)
    contract: "ContractInfo" = None
    node: object = None
    returns: list[str] = field(default_factory=list)

    @property
    def is_entry(self) -> bool:
        """Callable from outside: public/external, or default visibility (<0.5.0 semantics)."""
        if self.kind in ("fallback", "receive"):
            return True
        if self.kind != "function":
            return False
        return self.visibility in ("public", "external", "")

    @property
    def changes_state(self) -> bool:
        return self.mutability not in ("view", "pure")


@dataclass
class ContractInfo:
    name: str
    kind: str                       # contract | interface | library | abstract
    bases: list[str]
    line: int
    file: str
    state_vars: dict = field(default_factory=dict)      # name -> {type, line, constant}
    functions: list[FunctionInfo] = field(default_factory=list)
    modifiers: dict = field(default_factory=dict)       # name -> FunctionInfo
    usings: list[str] = field(default_factory=list)


@dataclass
class SourceFile:
    path: str
    source: bytes
    tree: object
    pragma: list                    # [(op, (major, minor, patch))]
    contracts: list[ContractInfo]
    has_error: bool

    @property
    def lines(self) -> list[str]:
        return self.source.decode("utf-8", "replace").splitlines()

    def code_line(self, n: int) -> str:
        ls = self.lines
        return ls[n - 1].strip() if 0 < n <= len(ls) else ""


_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_pragma(node) -> list:
    out, op = [], "="
    tok = next((c for c in node.named_children if c.type == "solidity_pragma_token"), None)
    if tok is None:
        return out
    for c in tok.named_children:
        if c.type == "solidity_version_comparison_operator":
            op = text(c).strip()
        elif c.type == "solidity_version":
            m = _VERSION_RE.match(text(c).strip())
            if m:
                out.append((op, tuple(int(x or 0) for x in m.groups())))
            op = "="
    return out


def _visibility_and_mutability(fn_node):
    vis = mut = ""
    mods = []
    for c in fn_node.named_children:
        if c.type == "visibility":
            vis = text(c).strip()
        elif c.type == "state_mutability":
            mut = text(c).strip()
        elif c.type == "modifier_invocation":
            ident = next((x for x in c.named_children if x.type == "identifier"), None)
            mods.append(text(ident) if ident is not None else text(c).split("(")[0].strip())
    # legacy `constant` functions behave like view
    if not mut and any(ch.type == "constant" for ch in fn_node.children):
        mut = "view"
    return vis, mut, mods


def _params(fn_node) -> list[str]:
    names = []
    for c in fn_node.named_children:
        targets = [c] if c.type == "parameter" else (
            [p for p in c.named_children if p.type == "parameter"] if c.type == "return_type_definition" else [])
        for p in targets:
            ident = [x for x in p.named_children if x.type == "identifier"]
            if ident:
                names.append(text(ident[-1]))
    return names


def _returns(fn_node) -> list[str]:
    out = []
    for c in fn_node.named_children:
        if c.type == "return_type_definition":
            for p in c.named_children:
                ident = [x for x in p.named_children if x.type == "identifier"] if p.type == "parameter" else []
                if ident:
                    out.append(text(ident[-1]))
    return out


def _locals(body) -> set[str]:
    out = set()
    if body is None:
        return out
    for n in walk(body):
        if n.type == "variable_declaration":
            ident = [x for x in n.named_children if x.type == "identifier"]
            if ident:
                out.add(text(ident[-1]))
    return out


_FN_KINDS = {"function_definition": "function", "constructor_definition": "constructor",
             "modifier_definition": "modifier", "fallback_receive_definition": None}


def _function(node, contract) -> FunctionInfo:
    kind = _FN_KINDS[node.type]
    if kind is None:
        kind = "receive" if any(c.type == "receive" for c in node.children) else "fallback"
    name_node = node.child_by_field_name("name") or next(
        (c for c in node.named_children if c.type == "identifier"), None)
    name = text(name_node) if name_node is not None and kind in ("function", "modifier") else kind
    vis, mut, mods = _visibility_and_mutability(node)
    body = next((c for c in node.named_children if c.type == "function_body"), None)
    return FunctionInfo(name=name, kind=kind, visibility=vis, mutability=mut, modifiers=mods,
                        params=_params(node), locals=_locals(body), line=line(node),
                        end_line=node.end_point[0] + 1, body=body, contract=contract, node=node,
                        returns=_returns(node))


_CONTRACT_KINDS = {"contract_declaration": "contract", "interface_declaration": "interface",
                   "library_declaration": "library"}


def parse_file(path: Path, display: str | None = None) -> SourceFile:
    parser, _ = get_parser()
    src = Path(path).read_bytes()
    tree = parser.parse(src)
    pragma, contracts = [], []
    for top in tree.root_node.named_children:
        if top.type == "pragma_directive":
            pragma.extend(_parse_pragma(top))
        elif top.type in _CONTRACT_KINDS:
            kind = _CONTRACT_KINDS[top.type]
            if any(c.type == "abstract" for c in top.children):
                kind = "abstract"
            name_node = top.child_by_field_name("name")
            bases = [text(b).split("(")[0].strip() for b in top.named_children if b.type == "inheritance_specifier"]
            ci = ContractInfo(name=text(name_node), kind=kind, bases=bases, line=line(top),
                              file=display or str(path))
            body = top.child_by_field_name("body")
            for m in (body.named_children if body is not None else []):
                if m.type == "state_variable_declaration":
                    ident = [x for x in m.named_children if x.type == "identifier"]
                    tnode = next((x for x in m.named_children if x.type == "type_name"), None)
                    if ident:
                        ci.state_vars[text(ident[-1])] = {
                            "type": text(tnode), "line": line(m),
                            "constant": any(c.type in ("constant", "immutable") for c in m.children)}
                elif m.type == "using_directive":
                    alias = next((x for x in m.named_children if x.type == "type_alias"), None)
                    if alias is not None:
                        ci.usings.append(text(alias))
                elif m.type in _FN_KINDS:
                    fi = _function(m, ci)
                    if fi.kind == "modifier":
                        ci.modifiers[fi.name] = fi
                    else:
                        if fi.kind == "function" and fi.name == ci.name:
                            fi.kind = "constructor"     # pre-0.4.22 constructor (a compile error from 0.5.0 on)
                        ci.functions.append(fi)
            contracts.append(ci)
    return SourceFile(path=display or str(path), source=src, tree=tree, pragma=pragma, contracts=contracts,
                      has_error=tree.root_node.has_error)


class Project:
    """All files of one scan: name-based resolution of inheritance and modifiers across them."""

    def __init__(self, files: list[SourceFile]):
        self.files = files
        self.contracts = {}
        for f in files:
            for c in f.contracts:
                self.contracts.setdefault(c.name, c)

    def linearized(self, contract: ContractInfo) -> list[ContractInfo]:
        seen, out, stack = set(), [], [contract]
        while stack:
            c = stack.pop(0)
            if c.name in seen:
                continue
            seen.add(c.name)
            out.append(c)
            stack.extend(self.contracts[b] for b in c.bases if b in self.contracts)
        return out

    def state_vars(self, contract: ContractInfo) -> dict:
        out = {}
        for c in reversed(self.linearized(contract)):
            out.update(c.state_vars)
        return out

    def modifier(self, contract: ContractInfo, name: str):
        for c in self.linearized(contract):
            if name in c.modifiers:
                return c.modifiers[name]
        return None

    def type_names(self, kinds=("contract", "interface", "abstract")) -> set[str]:
        return {n for n, c in self.contracts.items() if c.kind in kinds}
