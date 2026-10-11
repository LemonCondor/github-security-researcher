"""Minimal inter-procedural value-flow analysis for Go, purely syntactic (tree-sitter-go).

Reads local `.go` files only: no Go toolchain, no compilation, no execution, no network.

What it does
  * indexes functions, methods (with receiver type), struct fields, interfaces and imports;
  * resolves a call only when the target is statically unambiguous (same package, local module package,
    method on a receiver whose concrete type is known) -- everything else is recorded as NO_PROOF;
  * follows a value from a *seed* (an explicitly designated function parameter, or an explicit source
    expression such as `r.FormValue(..)` on a `*net/http.Request` parameter) through assignments, `+`,
    a small list of stdlib propagators and local helpers' return values, into call arguments, then into
    the matching parameter of the resolved callee, up to `max_depth` hops;
  * reports a path when the value reaches a *sink position* of a call matching a sink spec.

Precision choices (see `GoDataflow._reaching`):
  * a definition only reaches a use inside its own scope (`:=` / `var` in a sibling block do not leak);
  * a plain definition in an enclosing block, before the use, kills earlier definitions (`x = "const"`);
  * definitions located after the use are ignored (loop-carried flows are missed: false negatives, by design);
  * unknown external calls never propagate (implicit neutralisation: strconv, escaping, filepath.Base, ...).

Sources and sinks are abstract specs; categories are labels only. A path is a *potential* flow
("POTENTIAL"), never a confirmation; `path_to_evidence` caps it at moderate strength so it can never
satisfy the decision engine's CONFIRMED criteria on its own.
"""
from __future__ import annotations

import dataclasses
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ENGINE_VERSION = "go-dataflow/5"   # 3: struct field access paths; 4: declared result types; 5: provable *p
DEFAULT_MAX_DEPTH = 3            # resolved inter-function hops (A -> B -> C -> D)
SUMMARY_DEPTH = 2                # nested helper return summaries (x := f(g(y)))
MAX_FILE_BYTES = 1_000_000
MAX_PATHS = 2000                 # global budget, keeps the analysis bounded on large repositories
SKIP_DIRS = {"vendor", "testdata", "node_modules", ".git"}
PATH_STATUS = "POTENTIAL"        # the only status this module ever emits
EVIDENCE_MAX_STRENGTH = "moderate"
ALL_PARAMS = "*"                 # explicit opt-in: every parameter of every function is a seed (generic use)
GO_BUILTINS = {"append", "cap", "clear", "close", "complex", "copy", "delete", "imag", "len", "make", "max",
               "min", "new", "panic", "print", "println", "real", "recover"}
_SCOPES = {"block", "if_statement", "for_statement", "expression_switch_statement", "type_switch_statement",
           "select_statement", "expression_case", "type_case", "default_case", "communication_case"}
_HEADERS = _SCOPES - {"block"}

PkgKey = tuple[str, str]         # (directory relative to repo root, package name)


def _parser():
    try:
        import tree_sitter
        import tree_sitter_go
    except ImportError as e:     # pragma: no cover - depends on the environment
        raise RuntimeError("go_dataflow needs tree-sitter and tree-sitter-go (pip install '.[analysis]')") from e
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_go.language()))


def available() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_go  # noqa: F401
    except ImportError:
        return False
    return True


# --------------------------------------------------------------------------- model

@dataclass(frozen=True)
class TypeRef:
    """A type declared in the analysed module."""
    package: PkgKey
    name: str


@dataclass(frozen=True)
class ExtType:
    """A type from an imported package outside the module (e.g. database/sql.DB)."""
    import_path: str
    name: str


@dataclass
class Param:
    index: int
    name: str | None             # None for unnamed or blank (`_`) parameters
    type_text: str
    variadic: bool
    line: int
    column: int
    type_node: object = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "type_node"}


@dataclass
class GoFunction:
    package: str
    package_dir: str
    name: str
    receiver_type: str | None    # base type name, pointer/generics stripped
    receiver_name: str | None
    file: str
    start_line: int
    end_line: int
    parameters: list[Param]
    body: object = field(default=None, repr=False, compare=False)   # tree-sitter node, never serialised
    result: object = field(default=None, repr=False, compare=False)  # declared result type(s) node

    @property
    def key(self) -> str:
        return f"{self.package_dir or '.'}:{self.package}.{self.display}"

    @property
    def display(self) -> str:
        return f"{self.receiver_type}.{self.name}" if self.receiver_type else self.name

    def to_dict(self) -> dict:
        return {"key": self.key, "package": self.package, "package_dir": self.package_dir, "name": self.name,
                "receiver_type": self.receiver_type, "file": self.file, "start_line": self.start_line,
                "end_line": self.end_line, "parameters": [p.to_dict() for p in self.parameters]}


@dataclass(frozen=True)
class SinkSpec:
    """Abstract sink. import_path None = unqualified call `name(...)` (generic use); receiver = method on an
    external type of import_path; args = argument positions that are sinks (None = all)."""
    name: str
    import_path: str | None = None
    receiver: str | None = None
    args: tuple[int, ...] | None = None
    category: str = "generic"
    shell_prog: int | None = None    # index of the program arg: `sh -c X` also makes X a sink position

    @classmethod
    def parse(cls, spec: "str | SinkSpec") -> "SinkSpec":
        if isinstance(spec, SinkSpec):
            return spec
        if "." in spec:
            path, name = spec.rsplit(".", 1)
            return cls(name, path)
        return cls(spec)

    @property
    def label(self) -> str:
        base = f"{self.import_path}." if self.import_path else ""
        return f"{base}{self.receiver + '.' if self.receiver else ''}{self.name}"

    def positions(self, args: list) -> set[int] | None:
        if self.args is None:
            return None
        pos = set(self.args)
        p = self.shell_prog
        if p is not None and len(args) > p + 2:
            prog = _string_literal(args[p])
            if prog and prog.rsplit("/", 1)[-1] in ("sh", "bash", "dash", "zsh", "ksh") \
                    and _string_literal(args[p + 1]) == "-c":
                pos.add(p + 2)
        return pos


@dataclass
class CallSite:
    caller: str
    callee: str | None           # GoFunction.key when resolved
    callee_text: str
    file: str
    line: int
    column: int
    arguments: list[str]
    resolution: str              # "resolved" | "sink" | "propagator" | "no_proof"
    reason: str | None = None    # why it is not resolved
    sink: SinkSpec | None = None
    prop_args: tuple[int, ...] | None = None
    node: object = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("node", "sink", "prop_args")}
        d["sink"] = self.sink.label if self.sink else None
        return d


@dataclass
class FlowStep:
    file: str
    line: int
    column: int
    function: str
    kind: str    # source_param | source_expr | source_operator (diagnostic) | assign | propagate | summary_call | summary_param | return
    #              | deref | call | param | sink_arg
    detail: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class FlowPath:
    source: FlowStep
    steps: list[FlowStep]
    sink: FlowStep | None        # None when truncated
    depth: int                   # resolved inter-function hops
    truncated: bool
    category: str | None = None  # label of the sink spec
    entry: str | None = None     # function whose seed was explored (differs from source.function when the
    #                              source expression sits in a helper whose result flows back)
    status: str = PATH_STATUS

    def functions(self) -> list[str]:
        return [self.entry or self.source.function] + [s.function for s in self.steps if s.kind == "param"]

    def files(self) -> list[str]:
        out = [self.source.file] + [s.file for s in self.steps] + ([self.sink.file] if self.sink else [])
        return list(dict.fromkeys(out))

    def to_dict(self) -> dict:
        return {"source": self.source.to_dict(), "steps": [s.to_dict() for s in self.steps],
                "sink": self.sink.to_dict() if self.sink else None, "depth": self.depth,
                "truncated": self.truncated, "category": self.category, "entry": self.entry,
                "status": self.status,
                "functions": self.functions(), "files": self.files()}


@dataclass
class AnalysisResult:
    root: str
    files: list[str]
    functions: dict[str, GoFunction]
    calls: list[CallSite]
    paths: list[FlowPath]
    tainted_no_proof: list[dict]  # a tracked value reached a call we refused to resolve
    neutralized: list[dict]       # a tracked value reached a sink call outside a sink position
    cycles: list[list[str]]
    parse_errors: list[str]
    skipped_files: list[str]
    budget_exhausted: bool = False
    engine: str = ENGINE_VERSION
    field_refusals: list[dict] = field(default_factory=list)   # struct fields not tracked (NO_PROOF) and why
    pointer_refusals: list[dict] = field(default_factory=list) # `*p` whose pointee is not provable (NO_PROOF)

    @property
    def no_proof_calls(self) -> list[CallSite]:
        return [c for c in self.calls if c.resolution == "no_proof"]

    def to_dict(self) -> dict:
        return {"root": self.root, "engine": self.engine, "files": self.files,
                "functions": {k: f.to_dict() for k, f in self.functions.items()},
                "calls": [c.to_dict() for c in self.calls], "paths": [p.to_dict() for p in self.paths],
                "tainted_no_proof": self.tainted_no_proof, "neutralized": self.neutralized,
                "cycles": self.cycles, "parse_errors": self.parse_errors, "skipped_files": self.skipped_files,
                "budget_exhausted": self.budget_exhausted, "field_refusals": self.field_refusals,
                "pointer_refusals": self.pointer_refusals}


# --------------------------------------------------------------------------- security presets

def _sql_sinks() -> list[SinkSpec]:
    out = []
    for recv in ("DB", "Tx", "Conn"):
        for m in ("Query", "Exec", "QueryRow", "Prepare"):
            out.append(SinkSpec(m, "database/sql", recv, (0,), "sql-injection"))
            out.append(SinkSpec(m + "Context", "database/sql", recv, (1,), "sql-injection"))
    return out


# Only the query text is a sink: values passed as separate args (bound parameters) are not.
SECURITY_SINKS: tuple[SinkSpec, ...] = tuple(
    [SinkSpec("Command", "os/exec", None, (0,), "command-injection", shell_prog=0),
     SinkSpec("CommandContext", "os/exec", None, (1,), "command-injection", shell_prog=1)]
    + _sql_sinks()
    # File operations: a controlled value reaching a path argument. Traversal itself is NOT established.
    + [SinkSpec(n, "os", None, (0,), "path-traversal") for n in
       ("Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "Mkdir", "MkdirAll",
        "ReadDir")]
    + [SinkSpec("Rename", "os", None, (0, 1), "path-traversal")]
    + [SinkSpec(n, "io/ioutil", None, (0,), "path-traversal") for n in ("ReadFile", "WriteFile", "ReadDir")]
    # HTTP destination only (URL argument), never "any string reaching net/http".
    + [SinkSpec(n, "net/http", None, (0,), "ssrf") for n in ("Get", "Post", "Head", "PostForm")]
    + [SinkSpec("NewRequest", "net/http", None, (1,), "ssrf"),
       SinkSpec("NewRequestWithContext", "net/http", None, (2,), "ssrf")]
    + [SinkSpec(n, "net/http", "Client", (0,), "ssrf") for n in ("Get", "Post", "Head", "PostForm")])

# External calls whose result carries their argument (None = all args). Anything else stops the flow.
PROPAGATORS: dict[tuple[str, str], tuple[int, ...] | None] = {
    **{("fmt", n): None for n in ("Sprintf", "Sprint", "Sprintln")},
    **{("strings", n): (0,) for n in ("Join", "Replace", "ReplaceAll", "TrimSpace", "Trim", "TrimPrefix",
                                      "TrimSuffix", "TrimLeft", "TrimRight", "ToLower", "ToUpper", "Repeat")},
    ("path", "Join"): None, ("path", "Clean"): (0,),
    ("path/filepath", "Join"): None, ("path/filepath", "Clean"): (0,), ("path/filepath", "Abs"): (0,),
    ("path/filepath", "FromSlash"): (0,), ("path/filepath", "ToSlash"): (0,),
    ("net/url", "QueryUnescape"): (0,), ("net/url", "PathUnescape"): (0,),
    ("io", "ReadAll"): (0,), ("io/ioutil", "ReadAll"): (0,),
}

# Request-derived expressions on a `*net/http.Request` parameter `r`: r.<segments>. "()" marks a call.
HTTP_REQUEST = ExtType("net/http", "Request")
HTTP_SOURCES: frozenset[tuple[str, ...]] = frozenset({
    ("FormValue()",), ("PostFormValue()",), ("PathValue()",), ("Referer()",), ("UserAgent()",),
    ("Header", "Get()"), ("Header", "Values()"), ("URL", "Query()", "Get()"), ("URL", "Query()"),
    ("URL", "Path"), ("URL", "RawPath"), ("URL", "RawQuery"), ("Form", "Get()"), ("PostForm", "Get()"),
    ("Form",), ("PostForm",), ("Body",)})

# Return types of a few constructors / methods, so that `db, err := sql.Open(..)` types `db`.
KNOWN_RETURNS: dict[tuple[str, str | None, str], dict[int, ExtType]] = {
    ("database/sql", None, "Open"): {0: ExtType("database/sql", "DB")},
    ("database/sql", "DB", "Begin"): {0: ExtType("database/sql", "Tx")},
    ("database/sql", "DB", "BeginTx"): {0: ExtType("database/sql", "Tx")},
    ("database/sql", "DB", "Conn"): {0: ExtType("database/sql", "Conn")},
}
KNOWN_VARS: dict[tuple[str, str], ExtType] = {("net/http", "DefaultClient"): ExtType("net/http", "Client")}

# DIAGNOSTIC ONLY (never used by the scanner): operator-controlled inputs. Flags/env are configured by whoever
# deploys the program; they are not attacker input unless a separate justification says so.
OPERATOR_FLAG_PKGS = ("github.com/spf13/pflag", "flag")
OPERATOR_ENV = {("os", "Getenv"), ("os", "LookupEnv")}


# --------------------------------------------------------------------------- syntax helpers

def _t(n) -> str:
    return n.text.decode("utf-8", "replace")


def _pos(n) -> tuple[int, int]:
    return n.start_point[0] + 1, n.start_point[1] + 1


def _named(n) -> list:
    return [c for c in n.children if c.is_named and c.type != "comment"] if n is not None else []


def _walk(n, skip_func_literals: bool = True):
    """Pre-order traversal; nested func literals are skipped (closures are not followed)."""
    stack = [n]
    while stack:
        cur = stack.pop()
        yield cur
        kids = [c for c in cur.children if not (skip_func_literals and c.type == "func_literal")]
        stack.extend(reversed(kids))


def _contains(outer, inner) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


def _string_literal(n) -> str | None:
    if n is not None and n.type in ("interpreted_string_literal", "raw_string_literal"):
        return _t(n)[1:-1]
    return None


def _base_type_node(n):
    while n is not None and n.type in ("pointer_type", "parenthesized_type", "generic_type"):
        n = n.child_by_field_name("type") if n.type == "generic_type" else (_named(n) or [None])[0]
    return n


def _params(plist) -> list[Param]:
    out: list[Param] = []
    for d in _named(plist):
        if d.type not in ("parameter_declaration", "variadic_parameter_declaration"):
            continue
        typ = d.child_by_field_name("type")
        names = d.children_by_field_name("name")
        variadic = d.type == "variadic_parameter_declaration"
        for nm in names or [None]:
            name = _t(nm) if nm is not None and _t(nm) != "_" else None
            line, col = _pos(nm if nm is not None else d)
            out.append(Param(len(out), name, _t(typ) if typ is not None else "", variadic, line, col,
                             None if variadic else typ))
    return out


def _result_types(node) -> list:
    """Declared result types by position: `T`, `(T, error)`, `(a, b T, err error)`."""
    if node is None:
        return []
    if node.type != "parameter_list":
        return [node]
    out = []
    for d in _named(node):
        if d.type == "parameter_declaration":
            out += [d.child_by_field_name("type")] * max(1, len(d.children_by_field_name("name")))
        else:
            return []                      # unexpected form: no claim about positions
    return out


def _chain(e) -> tuple[object, tuple[str, ...]] | None:
    """`r.URL.Query().Get("x")` -> (identifier r, ("URL", "Query()", "Get()"))."""
    segs: list[str] = []
    while True:
        if e.type == "call_expression":
            fnode = e.child_by_field_name("function")
            if fnode is None or fnode.type != "selector_expression":
                return None
            segs.append(_t(fnode.child_by_field_name("field")) + "()")
            e = fnode.child_by_field_name("operand")
        elif e.type == "selector_expression":
            segs.append(_t(e.child_by_field_name("field")))
            e = e.child_by_field_name("operand")
        elif e.type == "identifier":
            return e, tuple(reversed(segs))
        else:
            return None


def _import_default_alias(path: str) -> str:
    last = path.rstrip("/").split("/")[-1]
    if re.fullmatch(r"v\d+", last) and "/" in path:          # example.com/mod/v2 -> mod
        last = path.rstrip("/").split("/")[-2]
    last = re.sub(r"\.v\d+$", "", last)                       # gopkg.in/yaml.v3 -> yaml
    return re.sub(r"^go-", "", last).replace("-", "_")


# --------------------------------------------------------------------------- index

@dataclass
class _File:
    rel: str
    pkg: PkgKey
    imports: dict[str, str]      # alias -> import path
    dot_imports: list[str]


@dataclass
class _TypeInfo:
    kind: str                    # struct | interface | alias | named
    fields: dict[str, tuple[object, _File]]


@dataclass
class _Def:
    name: str
    pos: int                     # start byte of the defined name
    rhs: object | None           # expression assigned (None: unknown / not trackable)
    type_node: object | None
    file: _File
    line: int
    column: int
    op: str                      # := | = | += | var | range
    ret_index: int               # which result of a multi-value call is assigned
    node: object                 # the defined identifier
    assign: object               # whole defining construct
    stmt: object | None          # statement directly inside a statement_list (None: header/init clause)
    scope: object | None         # visibility of `:=`/var/range definitions (None: whole function)

    def dominates(self, use) -> bool:
        """Plain definition, in a block enclosing the use, completed before it: earlier values are dead."""
        return (self.op in (":=", "=", "var") and self.stmt is not None and _contains(self.stmt.parent, use)
                and self.stmt.end_byte <= use.start_byte)


@dataclass
class _Facts:
    locals: set[str]
    defs: dict[str, list[_Def]]
    calls: list[CallSite]
    by_node: dict[tuple[int, int], CallSite]
    request_vars: frozenset[str]


@dataclass(frozen=True)
class _Seed:
    param: str | None            # tracked parameter (or receiver) name
    origin: bool                 # the parameter is the original source (emit a source step)
    request_vars: frozenset[str] = frozenset()   # *http.Request params whose source expressions count
    field: str | None = None     # tracked value is `param.field` (struct object passed by value or pointer)
    operator: bool = False       # DIAGNOSTIC ONLY: operator flags / env vars count as sources


class GoIndex:
    def __init__(self, root: Path, include_tests: bool = False):
        self.root = root.resolve()
        self.files: dict[str, _File] = {}
        self.functions: dict[str, GoFunction] = {}
        self.fn_file: dict[str, _File] = {}
        self.by_name: dict[tuple[PkgKey, str], list[str]] = {}
        self.methods: dict[tuple[TypeRef, str], list[str]] = {}
        self.types: dict[TypeRef, _TypeInfo] = {}
        self.pkg_by_dir: dict[str, set[str]] = {}
        self.modules: dict[str, str] = {}          # module path -> rel dir
        self.parse_errors: list[str] = []
        self.skipped: list[str] = []
        self._parser = _parser()
        self._load(include_tests)

    # ---- loading
    def _go_files(self, include_tests: bool) -> Iterable[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in SKIP_DIRS and not d.startswith((".", "_")))
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if fn == "go.mod" and not p.is_symlink():
                    self._read_gomod(p)
                if not fn.endswith(".go") or (fn.endswith("_test.go") and not include_tests):
                    continue
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    self.skipped.append(self._rel(p))
                    continue
                yield p

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def _read_gomod(self, p: Path) -> None:
        m = re.search(r"^\s*module\s+\"?([^\s\"]+)\"?", p.read_text(errors="replace"), re.M)
        if m:
            d = self._rel(p.parent)
            self.modules[m.group(1)] = "" if d == "." else d

    def _load(self, include_tests: bool) -> None:
        parsed = []
        for p in self._go_files(include_tests):
            tree = self._parser.parse(p.read_bytes())
            rel = self._rel(p)
            root = tree.root_node
            pc = next((c for c in root.children if c.type == "package_clause"), None)
            if pc is None or not _named(pc):
                self.parse_errors.append(rel)
                continue
            if root.has_error:
                self.parse_errors.append(rel)   # still indexed; erroneous declarations are skipped below
            d = self._rel(p.parent)
            d = "" if d == "." else d
            f = _File(rel, (d, _t(_named(pc)[0])), {}, [])
            self.files[rel] = f
            self.pkg_by_dir.setdefault(d, set()).add(f.pkg[1])
            parsed.append((f, root))
        for f, root in parsed:                      # imports need every package name first
            self._imports(f, root)
        for f, root in parsed:
            self._decls(f, root)

    def _imports(self, f: _File, root) -> None:
        for spec in (n for n in _walk(root) if n.type == "import_spec"):
            path_node = spec.child_by_field_name("path")
            if path_node is None:
                continue
            path = _t(path_node).strip('"`')
            name = spec.child_by_field_name("name")
            if name is not None and name.type == "dot":
                f.dot_imports.append(path)
            elif name is not None and name.type == "blank_identifier":
                continue
            else:
                local = self.package_for_import(path)
                alias = _t(name) if name is not None else (local[1] if local else _import_default_alias(path))
                f.imports[alias] = path

    def _decls(self, f: _File, root) -> None:
        for n in _named(root):
            if n.has_error:
                continue
            if n.type == "type_declaration":
                for spec in _named(n):
                    self._type_spec(f, spec)
            elif n.type in ("function_declaration", "method_declaration"):
                self._function(f, n)

    def _type_spec(self, f: _File, spec) -> None:
        name = spec.child_by_field_name("name")
        if name is None:
            return
        ref = TypeRef(f.pkg, _t(name))
        if spec.type == "type_alias":
            self.types[ref] = _TypeInfo("alias", {})
            return
        typ = spec.child_by_field_name("type")
        if typ is not None and typ.type == "struct_type":
            fields = {}
            for fd in (c for c in _walk(typ) if c.type == "field_declaration"):
                ft = fd.child_by_field_name("type")
                for fn in fd.children_by_field_name("name"):     # embedded fields have no name: not promoted
                    fields[_t(fn)] = (ft, f)
            self.types[ref] = _TypeInfo("struct", fields)
        elif typ is not None and typ.type == "interface_type":
            self.types[ref] = _TypeInfo("interface", {})
        else:
            self.types[ref] = _TypeInfo("named", {})

    def _function(self, f: _File, n) -> None:
        recv_type = recv_name = None
        if n.type == "method_declaration":
            rl = _params(n.child_by_field_name("receiver"))
            rdecl = [c for c in _named(n.child_by_field_name("receiver")) if c.type == "parameter_declaration"]
            base = _base_type_node(rdecl[0].child_by_field_name("type")) if rdecl else None
            if base is None or base.type != "type_identifier":
                return
            recv_type, recv_name = _t(base), (rl[0].name if rl else None)
        name = n.child_by_field_name("name")
        if name is None:
            return
        fn = GoFunction(f.pkg[1], f.pkg[0], _t(name), recv_type, recv_name, f.rel, n.start_point[0] + 1,
                        n.end_point[0] + 1, _params(n.child_by_field_name("parameters")),
                        n.child_by_field_name("body"), n.child_by_field_name("result"))
        key = fn.key
        while key in self.functions:                # duplicate (e.g. build-tag variants): keep both, ambiguous
            key += "'"
        self.functions[key] = fn
        self.fn_file[key] = f
        if recv_type:
            self.methods.setdefault((TypeRef(f.pkg, recv_type), fn.name), []).append(key)
        else:
            self.by_name.setdefault((f.pkg, fn.name), []).append(key)

    # ---- resolution helpers
    def package_for_import(self, path: str) -> PkgKey | None:
        """Map an import path to a package of a local module; None if external or ambiguous."""
        best = None
        for mod, d in self.modules.items():
            if (path == mod or path.startswith(mod + "/")) and (best is None or len(mod) > len(best[0])):
                best = (mod, d)
        if best is None:
            return None
        rest = path[len(best[0]):].lstrip("/")
        d = "/".join(x for x in (best[1], rest) if x)
        names = {p for p in self.pkg_by_dir.get(d, set()) if not p.endswith("_test")}
        return (d, names.pop()) if len(names) == 1 else None

    def resolve_type(self, node, f: _File) -> TypeRef | ExtType | None:
        node = _base_type_node(node)
        if node is None:
            return None
        if node.type == "type_identifier":
            ref = TypeRef(f.pkg, _t(node))
            return ref if ref in self.types else None
        if node.type == "qualified_type":
            alias = node.child_by_field_name("package")
            name = node.child_by_field_name("name")
            path = f.imports.get(_t(alias)) if alias is not None else None
            if path is None or name is None:
                return None
            pkg = self.package_for_import(path)
            if pkg is None:
                return ExtType(path, _t(name))
            ref = TypeRef(pkg, _t(name))
            return ref if ref in self.types else None
        return None


# --------------------------------------------------------------------------- analysis

class GoDataflow:
    def __init__(self, index: GoIndex, sinks: Iterable["str | SinkSpec"] = (), max_depth: int = DEFAULT_MAX_DEPTH,
                 max_paths: int = MAX_PATHS):
        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")
        self.ix = index
        self.sinks = [SinkSpec.parse(s) for s in sinks]
        self.max_depth = max_depth
        self.max_paths = max_paths
        self._facts: dict[str, _Facts] = {}
        self._summaries: dict[tuple, list[FlowStep] | None] = {}
        self._in_progress: set[tuple] = set()
        self.paths: list[FlowPath] = []
        self._path_keys: set[tuple] = set()
        self.tainted_no_proof: list[dict] = []
        self.neutralized: list[dict] = []
        self.cycles: list[list[str]] = []
        self.field_refusals: list[dict] = []
        self.pointer_refusals: list[dict] = []
        self._structs: dict[tuple[str, str], tuple[TypeRef | None, str]] = {}
        self._typing: dict[tuple[str, str], TypeRef | ExtType | None] = {}   # vars being typed (recursion guard)
        self.budget_exhausted = False

    # ---- per-function facts
    def facts(self, key: str) -> _Facts:
        if key not in self._facts:
            self._facts[key] = self._compute_facts(key)
        return self._facts[key]

    def _compute_facts(self, key: str) -> _Facts:
        fn, f = self.ix.functions[key], self.ix.fn_file[key]
        defs: dict[str, list[_Def]] = {}
        names: set[str] = {p.name for p in fn.parameters if p.name}
        if fn.receiver_name:
            names.add(fn.receiver_name)
        reqs = frozenset(p.name for p in fn.parameters
                         if p.name and self.ix.resolve_type(p.type_node, f) == HTTP_REQUEST)
        if fn.body is None:
            return _Facts(names, defs, [], {}, reqs)
        for n in _walk(fn.body, skip_func_literals=False):         # every local name, closures included
            if n.type in ("short_var_declaration", "range_clause"):
                for c in _named(n.child_by_field_name("left")):
                    if c.type == "identifier":
                        names.add(_t(c))
            elif n.type in ("var_spec", "const_spec", "parameter_declaration"):
                names.update(_t(c) for c in n.children_by_field_name("name"))
        for n in _walk(fn.body):
            if n.type in ("short_var_declaration", "assignment_statement"):
                self._assign_defs(n, f, defs)
                if n.type == "assignment_statement":
                    self._field_assign_defs(n, f, defs, names)
            elif n.type == "var_spec":
                vals = _named(n.child_by_field_name("value"))
                nms = n.children_by_field_name("name")
                typ = n.child_by_field_name("type")
                for i, nm in enumerate(nms):
                    rhs, ri = self._pair(vals, len(nms), i)
                    self._add_def(defs, nm, rhs, typ, f, "var", ri, n)
            elif n.type == "range_clause":
                left = [c for c in _named(n.child_by_field_name("left")) if c.type == "identifier"]
                for i, c in enumerate(left):
                    # only the element variable carries the ranged value; the key/index does not
                    self._add_def(defs, c, n.child_by_field_name("right") if i == 1 else None, None, f,
                                  "range", 0, n)
        # Second pass: every definition must be known before a receiver type is judged unambiguous.
        calls = [self._call_site(fn, f, n, names, defs) for n in _walk(fn.body) if n.type == "call_expression"]
        return _Facts(names, defs, calls, {(c.node.start_byte, c.node.end_byte): c for c in calls}, reqs)

    @staticmethod
    def _pair(right: list, n_left: int, i: int) -> tuple[object | None, int]:
        if len(right) == n_left:
            return right[i], 0
        if len(right) == 1 and right[0].type == "call_expression":     # a, b := f(x)
            return right[0], i
        return None, 0

    def _assign_defs(self, n, f: _File, defs) -> None:
        op = n.child_by_field_name("operator")
        op = _t(op) if op is not None else ":="
        left = _named(n.child_by_field_name("left"))
        right = _named(n.child_by_field_name("right"))
        for i, lhs in enumerate(left):
            if lhs.type != "identifier" or _t(lhs) == "_":
                continue
            rhs, ri = self._pair(right, len(left), i) if op in (":=", "=", "+=") else (None, 0)
            self._add_def(defs, lhs, rhs, None, f, op, ri, n)

    def _field_assign_defs(self, n, f: _File, defs, names) -> None:
        """`x.F = e` (x a local/param/receiver) -> definition of the access path "x.F"."""
        op = n.child_by_field_name("operator")
        op = _t(op) if op is not None else "="
        left = _named(n.child_by_field_name("left"))
        right = _named(n.child_by_field_name("right"))
        for i, lhs in enumerate(left):
            if lhs.type != "selector_expression":
                continue
            base = lhs.child_by_field_name("operand")
            if base.type != "identifier" or _t(base) not in names:
                continue
            rhs, ri = self._pair(right, len(left), i) if op in ("=", "+=") else (None, 0)
            key = f"{_t(base)}.{_t(lhs.child_by_field_name('field'))}"
            self._add_def(defs, lhs, rhs, None, f, op, ri, n, name=key)

    @staticmethod
    def _add_def(defs, name_node, rhs, typ, f: _File, op: str, ret_index: int, assign, name: str | None = None) -> None:
        stmt = assign
        while stmt is not None and stmt.parent is not None and stmt.parent.type != "statement_list":
            if stmt.parent.type in _HEADERS:
                stmt = None                       # init/header clause: never dominates
                break
            stmt = stmt.parent
        if stmt is not None and stmt.parent is None:
            stmt = None
        scope = None
        if op in (":=", "var", "range"):
            scope = assign.parent
            while scope is not None and scope.type not in _SCOPES:
                scope = scope.parent
        line, col = _pos(name_node)
        name = name or _t(name_node)
        defs.setdefault(name, []).append(
            _Def(name, name_node.start_byte, rhs, typ, f, line, col, op, ret_index, name_node, assign, stmt, scope))

    # ---- types of local expressions (for method receivers)
    def _var_type(self, fn: GoFunction, name: str, defs, names, depth: int = 0) -> tuple[TypeRef | ExtType | None, str]:
        """Type of local `name` if every binding agrees on one type.
        Self-referential bindings (`n = n.Next()`) are checked optimistically: the type comes from the other
        bindings and the recursive ones must yield the same type under that assumption, else NO_PROOF."""
        f = self.ix.fn_file[fn.key]
        ck = (fn.key, name)
        if ck in self._typing:
            assumed = self._typing[ck]
            return (assumed, "") if assumed is not None else (None, "receiver type unknown (self-referential definition)")
        if depth > 12:
            return None, "receiver type unknown (typing too deep)"
        cands: set = set()
        reasons: list[str] = []
        if fn.receiver_name == name:
            cands.add(TypeRef(f.pkg, fn.receiver_type))
        for p in fn.parameters:
            if p.name == name:
                cands.add(self.ix.resolve_type(p.type_node, f) if p.type_node is not None else None)
        recursive = []
        for d in defs.get(name, []):
            if d.type_node is not None:
                cands.add(self.ix.resolve_type(d.type_node, f))
            elif d.rhs is None:
                cands.add(None)
            elif any(n.type == "identifier" and _t(n) == name for n in _walk(d.rhs)):
                recursive.append(d)
            else:
                cands.add(self._def_type(fn, d, defs, names, depth, reasons))
        if recursive:
            assumed = next(iter(cands)) if len(cands) == 1 and None not in cands else None
            self._typing[ck] = assumed
            try:
                for d in recursive:
                    cands.add(self._def_type(fn, d, defs, names, depth, reasons) if assumed is not None else None)
            finally:
                del self._typing[ck]
        if len(cands) > 1:
            return None, "receiver type ambiguous"
        if not cands or None in cands:
            return None, "receiver type unknown" + (f": {reasons[0]}" if reasons else "")
        return next(iter(cands)), ""

    def _def_type(self, fn: GoFunction, d: _Def, defs, names, depth: int, reasons: list[str]):
        if d.rhs.type == "call_expression":
            typ, why = self._call_result_type(fn, d.rhs, d.ret_index, defs, names, depth + 1)
            if typ is None and why:
                reasons.append(why)
            return typ
        return self._expr_type(fn, d.rhs, d.ret_index, defs, names, depth + 1)

    def _expr_type(self, fn: GoFunction, e, ret_index: int, defs, names, depth: int = 0):
        f = self.ix.fn_file[fn.key]
        if depth > 12:
            return None
        if e.type == "unary_expression" and e.child_by_field_name("operand") is not None:
            if _t(e.child_by_field_name("operator") or e.children[0]) == "&":
                return self._expr_type(fn, e.child_by_field_name("operand"), 0, defs, names, depth + 1)
            return None
        if e.type == "composite_literal":
            return self.ix.resolve_type(e.child_by_field_name("type"), f)
        if e.type != "call_expression":
            return None
        return self._call_result_type(fn, e, ret_index, defs, names, depth)[0]

    def _call_result_type(self, fn: GoFunction, e, ret_index: int, defs, names, depth: int = 0):
        """Type of result `ret_index` of call `e`, ONLY from the uniquely resolved callee's declared signature
        (or the small KNOWN_RETURNS table for stdlib). Returns (type, "") or (None, reason) -> NO_PROOF."""
        f = self.ix.fn_file[fn.key]
        if depth > 12:
            return None, "result type: call chain too deep"
        func = e.child_by_field_name("function")
        if _t(func) == "new":
            args = _named(e.child_by_field_name("arguments"))
            return (self.ix.resolve_type(args[0], f) if len(args) == 1 else None), "new(T) type unresolved"
        callee: str | None = None
        if func.type == "identifier":
            if _t(func) in names:
                return None, "result type: call through a local function value"
            cands = self.ix.by_name.get((f.pkg, _t(func)), [])
            if len(cands) != 1:
                return None, f"result type: {_t(func)} not uniquely declared in the package"
            callee = cands[0]
        elif func.type == "selector_expression":
            operand, member = func.child_by_field_name("operand"), _t(func.child_by_field_name("field"))
            if operand.type == "identifier" and _t(operand) not in names and _t(operand) in f.imports:
                path = f.imports[_t(operand)]
                pkg = self.ix.package_for_import(path)
                if pkg is None:
                    known = KNOWN_RETURNS.get((path, None, member), {}).get(ret_index)
                    return (known, "") if known else (None, f"result type of external {path}.{member} unknown")
                cands = self.ix.by_name.get((pkg, member), [])
                if len(cands) != 1:
                    return None, f"result type: {member} not uniquely declared in {path}"
                callee = cands[0]
            else:
                typ, why = self._operand_type(fn, operand, names, defs, depth + 1)
                if typ is None:
                    return None, why
                if isinstance(typ, ExtType):
                    known = KNOWN_RETURNS.get((typ.import_path, typ.name, member), {}).get(ret_index)
                    return (known, "") if known else \
                        (None, f"result type of external method {typ.import_path}.{typ.name}.{member} unknown")
                info = self.ix.types.get(typ)
                if info is None or info.kind in ("interface", "alias"):
                    return None, f"result type: {typ.name} is an {info.kind if info else 'unknown type'}"
                cands = self.ix.methods.get((typ, member), [])
                if len(cands) != 1:
                    return None, f"result type: method {typ.name}.{member} not uniquely declared"
                callee = cands[0]
        else:
            return None, f"result type: unsupported callee form {func.type}"
        results = _result_types(self.ix.functions[callee].result)
        if ret_index >= len(results):
            return None, f"result type: {self.ix.functions[callee].display} declares no result {ret_index}"
        typ = self.ix.resolve_type(results[ret_index], self.ix.fn_file[callee])   # callee's package context
        if typ is None:
            return None, f"result type {_t(results[ret_index])} of {self.ix.functions[callee].display} unresolved"
        return typ, ""

    def _operand_type(self, fn: GoFunction, e, names, defs, depth: int = 0):
        f = self.ix.fn_file[fn.key]
        if depth > 12:
            return None, "receiver expression too deep"
        if e.type == "parenthesized_expression" and _named(e):
            return self._operand_type(fn, _named(e)[0], names, defs, depth + 1)
        if e.type == "identifier":
            if _t(e) not in names:
                return None, "receiver is not a local variable (package-level or unknown)"
            return self._var_type(fn, _t(e), defs, names, depth + 1)
        if e.type == "selector_expression":
            op = e.child_by_field_name("operand")
            fld = _t(e.child_by_field_name("field"))
            if op.type == "identifier" and _t(op) not in names and _t(op) in f.imports:
                known = KNOWN_VARS.get((f.imports[_t(op)], fld))
                return (known, "") if known else (None, f"package-level value {_t(e)} has unknown type")
            base, why = self._operand_type(fn, op, names, defs, depth + 1)
            if base is None:
                return None, why
            info = self.ix.types.get(base) if isinstance(base, TypeRef) else None
            if info is None or info.kind != "struct" or fld not in info.fields:
                return None, f"field {fld} not found on {base.name}"
            tnode, tfile = info.fields[fld]
            ref = self.ix.resolve_type(tnode, tfile)
            return (ref, "") if ref else (None, f"type of field {fld} unknown")
        if e.type == "call_expression":
            typ, why = self._call_result_type(fn, e, 0, defs, names, depth + 1)
            return (typ, "") if typ is not None else (None, why)
        return None, f"unsupported receiver expression {e.type}"

    # ---- call resolution
    def _call_site(self, fn: GoFunction, f: _File, n, names, defs) -> CallSite:
        func = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        line, col = _pos(n)
        site = CallSite(fn.key, None, _t(func), f.rel, line, col, [_t(a) for a in _named(args)], "no_proof",
                        node=n)

        def done(resolution: str, callee: str | None = None, reason: str | None = None,
                 sink: SinkSpec | None = None, prop: tuple[int, ...] | None = None) -> CallSite:
            site.resolution, site.callee, site.reason, site.sink, site.prop_args = \
                resolution, callee, reason, sink, prop
            return site

        if func.type == "identifier":
            name = _t(func)
            if name in names:
                return done("no_proof", reason="call through a local function value")
            spec = next((s for s in self.sinks if s.import_path is None and s.name == name), None)
            if spec:
                return done("sink", sink=spec)
            cands = self.ix.by_name.get((f.pkg, name), [])
            if len(cands) == 1:
                return done("resolved", cands[0])
            if len(cands) > 1:
                return done("no_proof", reason="ambiguous: several declarations (build tags?)")
            if name in GO_BUILTINS:
                return done("no_proof", reason="builtin")
            if name == "string" or TypeRef(f.pkg, name) in self.ix.types:
                return done("no_proof", reason="type conversion")
            if f.dot_imports:
                return done("no_proof", reason="may come from a dot-import")
            return done("no_proof", reason="no local declaration")

        if func.type == "selector_expression":
            operand = func.child_by_field_name("operand")
            member = _t(func.child_by_field_name("field"))
            if operand.type == "identifier" and _t(operand) not in names and _t(operand) in f.imports:
                path = f.imports[_t(operand)]
                spec = next((s for s in self.sinks
                             if s.import_path == path and s.receiver is None and s.name == member), None)
                if spec:
                    return done("sink", sink=spec)
                if (path, member) in PROPAGATORS:
                    return done("propagator", prop=PROPAGATORS[(path, member)])
                pkg = self.ix.package_for_import(path)
                if pkg is None:
                    return done("no_proof", reason=f"external or unresolved package {path}")
                cands = self.ix.by_name.get((pkg, member), [])
                if len(cands) == 1:
                    return done("resolved", cands[0])
                return done("no_proof", reason=f"{member} not uniquely declared in {path}")
            typ, why = self._operand_type(fn, operand, names, defs)
            if typ is None:
                return done("no_proof", reason=why)
            if isinstance(typ, ExtType):
                spec = next((s for s in self.sinks if s.import_path == typ.import_path and s.receiver == typ.name
                             and s.name == member), None)
                if spec:
                    return done("sink", sink=spec)
                return done("no_proof", reason=f"method of external type {typ.import_path}.{typ.name}")
            info = self.ix.types.get(typ)
            if info is None or info.kind in ("interface", "alias"):
                return done("no_proof", reason=f"{typ.name} is an {info.kind if info else 'unknown type'}: "
                                               "dynamic dispatch not resolved")
            cands = self.ix.methods.get((typ, member), [])
            if len(cands) == 1:
                return done("resolved", cands[0])
            return done("no_proof", reason=f"method {typ.name}.{member} not uniquely declared (promoted?)")

        return done("no_proof", reason=f"unsupported callee form {func.type}")

    # ---- struct fields
    @staticmethod
    def _fresh_object(rhs) -> bool:
        """Value that creates a new object no one else references: T{..}, &T{..}, new(T)."""
        if rhs is None:
            return False
        if rhs.type == "unary_expression" and _t(rhs.child_by_field_name("operator") or rhs.children[0]) == "&":
            rhs = rhs.child_by_field_name("operand")
        if rhs.type == "composite_literal":
            return True
        return rhs.type == "call_expression" and _t(rhs.child_by_field_name("function")) == "new"

    @staticmethod
    def _literal_field(rhs, field_name: str):
        """Value of keyed element `field_name` in T{..} / &T{..}; None if absent (zero value) or not a literal."""
        if rhs is None:
            return None
        if rhs.type == "unary_expression" and rhs.child_by_field_name("operand") is not None:
            rhs = rhs.child_by_field_name("operand")
        if rhs.type != "composite_literal":
            return None
        for el in _named(rhs.child_by_field_name("body")):
            if el.type != "keyed_element":
                continue
            kv = _named(el)
            if len(kv) == 2 and _t(kv[0]) == field_name:
                return _named(kv[1])[0] if kv[1].type == "literal_element" and _named(kv[1]) else kv[1]
        return None

    def _struct_of(self, key: str, var: str) -> tuple[TypeRef | None, str]:
        """Struct type of local `var` when its fields can be tracked soundly, else (None, reason).
        Requires one resolved local struct type, an object that is a parameter/receiver or freshly built
        here, and no alias of it created in this function (y := x, y = &x, s.f = x, T{f: x})."""
        ck = (key, var)
        if ck in self._structs:
            return self._structs[ck]
        fn, facts = self.ix.functions[key], self.facts(key)
        typ, why = self._var_type(fn, var, facts.defs, facts.locals)
        out: tuple[TypeRef | None, str]
        if not isinstance(typ, TypeRef):
            out = (None, why or "type outside the module")
        elif self.ix.types[typ].kind != "struct":
            out = (None, f"{typ.name} is not a struct ({self.ix.types[typ].kind})")
        else:
            out = (typ, "")
            for d in facts.defs.get(var, []):
                if not (self._fresh_object(d.rhs) or (d.rhs is None and d.op == "var")):
                    out = (None, f"{var} obtained from an expression whose object identity is unknown")
                    break
            if out[0] is not None and self._aliased(fn, var):
                out = (None, f"{var} is aliased in {fn.display}")
        self._structs[ck] = out
        return out

    @staticmethod
    def _aliased(fn: GoFunction, var: str) -> bool:
        for n in _walk(fn.body) if fn.body is not None else []:
            if n.type != "identifier" or _t(n) != var:
                continue
            e = n.parent
            if e is not None and e.type == "unary_expression" and _t(e.child_by_field_name("operator") or e.children[0]) == "&":
                n, e = e, e.parent                                  # &x
            if e is None:
                continue
            if e.type == "expression_list" and e.parent is not None and \
                    e.parent.type in ("short_var_declaration", "assignment_statement", "var_spec") and \
                    e.parent.child_by_field_name("left") != e:
                return True                                         # y := x / y = &x / var y = x
            if e.type == "literal_element" and e.parent is not None and e.parent.type == "keyed_element" \
                    and _named(e.parent)[-1] == e:
                return True                                         # T{f: x}
        return False

    def _field_reaching(self, var: str, fld: str, use, facts: _Facts) -> tuple[list[_Def], bool]:
        """Definitions of access path var.fld reaching `use`: explicit `var.fld = e` plus every (re)definition of
        the whole object (literal element value, or zero/unknown). Same scope/kill rules as variables."""
        whole = [dataclasses.replace(d, name=f"{var}.{fld}", rhs=self._literal_field(d.rhs, fld), op=d.op)
                 for d in facts.defs.get(var, [])]
        tmp = _Facts(facts.locals, {f"{var}.{fld}": facts.defs.get(f"{var}.{fld}", []) + whole}, [], {},
                     facts.request_vars)
        return self._reaching(f"{var}.{fld}", use, tmp)

    def _field_taint(self, var: str, fld: str, use, seed: _Seed, key: str, seen: frozenset,
                     sdepth: int) -> list[FlowStep] | None:
        fn, facts = self.ix.functions[key], self.facts(key)
        typ, why = self._struct_of(key, var)
        if typ is None or fld not in self.ix.types[typ].fields:
            if typ is None and (facts.defs.get(f"{var}.{fld}") or (seed.param == var and seed.field == fld)
                                or why == f"{var} is aliased in {fn.display}"):
                line, _ = _pos(use)
                self.field_refusals.append({"function": fn.display, "file": fn.file, "line": line,
                                            "field": f"{var}.{fld}", "reason": why})
            return None
        defs, param_reaches = self._field_reaching(var, fld, use, facts)
        if param_reaches and seed.param == var and seed.field == fld:
            return []
        name = f"{var}.{fld}"
        for d in sorted(defs, key=lambda d: d.pos):
            if (name, d.pos) in seen or d.rhs is None:
                continue
            s2 = seen | {(name, d.pos)}
            chain = self._taint(d.rhs, seed, key, s2, sdepth, d.ret_index)
            if chain is None and d.op == "+=":
                chain = self._taint(d.node, seed, key, s2, sdepth)
            if chain is not None:
                return chain + [FlowStep(d.file.rel, d.line, d.column, fn.display, "assign",
                                         f"{name} {d.op} {_t(d.rhs)}"[:200])]
        return None

    def _object_arg(self, key: str, e) -> str | None:
        """`x` or `&x` where x is a local whose struct fields are trackable."""
        if e.type == "unary_expression" and _t(e.child_by_field_name("operator") or e.children[0]) == "&":
            e = e.child_by_field_name("operand")
        if e is None or e.type != "identifier" or _t(e) not in self.facts(key).locals:
            return None
        return _t(e) if self._struct_of(key, _t(e))[0] is not None else None

    # ---- value tracking
    def _reaching(self, name: str, use, facts: _Facts) -> tuple[list[_Def], bool]:
        """Definitions of `name` that may reach `use`, and whether the parameter value still may."""
        cands = [d for d in facts.defs.get(name, [])
                 if d.pos < use.start_byte and not _contains(d.assign, use)
                 and (d.scope is None or _contains(d.scope, use))]
        dom = [d for d in cands if d.dominates(use)]
        if dom:
            last = max(dom, key=lambda d: d.pos)
            return [d for d in cands if d.pos >= last.pos], False
        return cands, True

    def _taint(self, e, seed: _Seed, key: str, seen: frozenset, sdepth: int,
               ret_index: int = 0) -> list[FlowStep] | None:
        """Steps showing how the seed reaches expression `e`; None if it does not.
        The first step is the source step when the seed is an origin."""
        if e is None:
            return None
        fn = self.ix.functions[key]
        t = e.type
        if t in ("variadic_argument", "parenthesized_expression") and _named(e):
            return self._taint(_named(e)[0], seed, key, seen, sdepth)
        if t == "binary_expression":
            if _t(e.child_by_field_name("operator")) != "+":
                return None
            for side in ("left", "right"):
                r = self._taint(e.child_by_field_name(side), seed, key, seen, sdepth)
                if r is not None:
                    return r
            return None
        if t in ("index_expression", "slice_expression"):
            return self._taint(e.child_by_field_name("operand"), seed, key, seen, sdepth)
        if t == "type_conversion_expression":
            return self._taint(e.child_by_field_name("operand"), seed, key, seen, sdepth)
        if seed.request_vars and t in ("call_expression", "selector_expression"):
            ch = _chain(e)
            if ch and _t(ch[0]) in seed.request_vars and ch[1] in HTTP_SOURCES:
                line, col = _pos(e)
                return [FlowStep(fn.file, line, col, fn.display, "source_expr", f"http request: {_t(e)[:120]}")]
        if seed.operator:
            src = self._operator_source(e, key)
            if src is not None:
                return [src]
        if t == "call_expression":
            return self._call_taint(e, seed, key, seen, sdepth, ret_index)
        if t == "selector_expression":
            base = e.child_by_field_name("operand")
            if base.type == "identifier" and _t(base) in self.facts(key).locals:
                return self._field_taint(_t(base), _t(e.child_by_field_name("field")), e, seed, key, seen, sdepth)
            self._nested_refusal(e, key)
            return None
        if t == "unary_expression" and _t(e.child_by_field_name("operator") or e.children[0]) == "*":
            return self._deref_taint(e, seed, key, seen, sdepth)
        if t != "identifier":
            return None
        return self._var_taint(_t(e), e, seed, key, seen, sdepth)

    def _var_taint(self, name: str, use, seed: _Seed, key: str, seen: frozenset, sdepth: int) -> list[FlowStep] | None:
        """Steps showing how the seed reaches local variable `name` as read at node `use`."""
        fn = self.ix.functions[key]
        facts = self.facts(key)
        defs, param_reaches = self._reaching(name, use, facts)
        if param_reaches and seed.param == name and seed.field is None:
            if not seed.origin:
                return []
            p = next(p for p in fn.parameters if p.name == name)
            return [FlowStep(fn.file, p.line, p.column, fn.display, "source_param", f"param {p.index} ({name})")]
        for d in sorted(defs, key=lambda d: d.pos):
            if (name, d.pos) in seen:
                continue
            s2 = seen | {(name, d.pos)}
            chain = self._taint(d.rhs, seed, key, s2, sdepth, d.ret_index) if d.rhs is not None else None
            if chain is None and d.op == "+=":
                chain = self._taint(d.node, seed, key, s2, sdepth)     # old value of `x` in `x += y`
            if chain is not None:
                detail = f"{name} {d.op} {_t(d.rhs) if d.rhs is not None else ''}".strip()
                return chain + [FlowStep(d.file.rel, d.line, d.column, fn.display, "assign", detail[:200])]
        return None

    def _nested_refusal(self, e, key: str) -> None:
        """`x.a.b` rooted at a local of a module struct type: nested access paths are not tracked -> NO_PROOF."""
        root = e
        while root.type == "selector_expression":
            root = root.child_by_field_name("operand")
        fn, facts = self.ix.functions[key], self.facts(key)
        if root.type != "identifier" or _t(root) not in facts.locals:
            return
        typ, _ = self._var_type(fn, _t(root), facts.defs, facts.locals)
        if isinstance(typ, TypeRef) and self.ix.types[typ].kind == "struct":
            line, _ = _pos(e)
            self.field_refusals.append({"function": fn.display, "file": fn.file, "line": line, "field": _t(e),
                                        "reason": "nested access path not supported"})

    def _pointee(self, key: str, ptr: str, use) -> tuple[str | None, _Def | None, str]:
        """Local variable that `*ptr` designates at `use`, only when provable: every reaching definition of ptr is
        `&x` with the same local x, ptr is only ever dereferenced for reading (no copy, no call argument, no
        `*ptr = ..`, closures included) and &x is taken nowhere else. Else (None, def, reason) -> NO_PROOF."""
        fn, facts = self.ix.functions[key], self.facts(key)
        if ptr not in facts.locals:
            return None, None, f"pointer {ptr} is not a local variable"
        defs, param_reaches = self._reaching(ptr, use, facts)
        if param_reaches and (ptr == fn.receiver_name or any(p.name == ptr for p in fn.parameters)):
            return None, None, f"pointer {ptr} comes from a parameter: pointee unknown"
        if not defs:
            return None, None, f"pointer {ptr} has no visible definition"
        targets: dict[str, _Def] = {}
        for d in defs:
            r = d.rhs
            if r is None or r.type != "unary_expression" or _t(r.child_by_field_name("operator") or r.children[0]) != "&" \
                    or r.child_by_field_name("operand").type != "identifier":
                return None, None, f"pointer {ptr} not built by &x in this function ({r.type if r is not None else 'no value'})"
            x = _t(r.child_by_field_name("operand"))
            if x not in facts.locals:
                return None, None, f"pointer {ptr} targets a non-local variable {x}"
            targets.setdefault(x, d)
        if len(targets) > 1:
            return None, None, f"pointer {ptr} has several possible pointees ({', '.join(sorted(targets))})"
        (x, d), = targets.items()
        def_nodes = {dd.node.start_byte for dd in facts.defs.get(ptr, [])}
        own_rhs = {dd.rhs.start_byte for dd in facts.defs.get(ptr, []) if dd.rhs is not None}
        for n in _walk(fn.body, skip_func_literals=False):
            if n.type == "identifier" and _t(n) == ptr and n.start_byte not in def_nodes:
                par = n.parent
                if par is None or par.type != "unary_expression" or _t(par.child_by_field_name("operator") or par.children[0]) != "*":
                    return None, d, f"pointer {ptr} escapes (used other than *{ptr})"
                stmt = par.parent.parent if par.parent is not None else None
                if par.parent.type == "expression_list" and stmt is not None and \
                        stmt.type in ("assignment_statement", "inc_statement", "dec_statement") and \
                        stmt.child_by_field_name("left") == par.parent:
                    return None, d, f"write through pointer {ptr}"
            elif n.type in ("inc_statement", "dec_statement") and _named(n) and _t(_named(n)[0]) == f"*{ptr}":
                return None, d, f"write through pointer {ptr}"
            elif n.type == "unary_expression" and n.start_byte not in own_rhs and \
                    _t(n.child_by_field_name("operator") or n.children[0]) == "&" and \
                    n.child_by_field_name("operand") is not None and _t(n.child_by_field_name("operand")) == x:
                return None, d, f"address of {x} also taken elsewhere"
        return x, d, ""

    def _deref_taint(self, e, seed: _Seed, key: str, seen: frozenset, sdepth: int) -> list[FlowStep] | None:
        ptr = e.child_by_field_name("operand")
        if ptr is None or ptr.type != "identifier":
            return None
        fn = self.ix.functions[key]
        x, d, why = self._pointee(key, _t(ptr), e)
        if x is None:
            line, _ = _pos(e)
            self.pointer_refusals.append({"function": fn.display, "file": fn.file, "line": line,
                                          "deref": _t(e), "reason": why})
            return None
        chain = self._var_taint(x, e, seed, key, seen, sdepth)      # value of x where *ptr is read
        if chain is None:
            return None
        return chain + [FlowStep(d.file.rel, d.line, d.column, fn.display, "deref",
                                 f"*{_t(ptr)} -> {x} ({_t(ptr)} {d.op} &{x})")]

    def _operator_source(self, e, key: str) -> FlowStep | None:
        """DIAGNOSTIC ONLY: `*flX` with flX := pflag/flag.X(..), or os.Getenv/os.LookupEnv(..)."""
        fn, f = self.ix.functions[key], self.ix.fn_file[key]
        line, col = _pos(e)
        if e.type == "unary_expression" and _t(e.child_by_field_name("operator") or e.children[0]) == "*":
            v = e.child_by_field_name("operand")
            if v is not None and v.type == "identifier":
                for d in self.facts(key).defs.get(_t(v), []):
                    if d.rhs is not None and d.rhs.type == "call_expression":
                        fnode = d.rhs.child_by_field_name("function")
                        op = fnode.child_by_field_name("operand") if fnode.type == "selector_expression" else None
                        if op is not None and f.imports.get(_t(op)) in OPERATOR_FLAG_PKGS:
                            return FlowStep(fn.file, line, col, fn.display, "source_operator",
                                            f"operator flag: {_t(e)} ({_t(d.rhs)[:60]})")
        if e.type == "call_expression":
            fnode = e.child_by_field_name("function")
            if fnode.type == "selector_expression":
                op = fnode.child_by_field_name("operand")
                if op.type == "identifier" and (f.imports.get(_t(op)), _t(fnode.child_by_field_name("field"))) \
                        in OPERATOR_ENV:
                    return FlowStep(fn.file, line, col, fn.display, "source_operator",
                                    f"operator env: {_t(e)[:80]}")
        return None

    def _call_taint(self, e, seed: _Seed, key: str, seen, sdepth: int, ret_index: int) -> list[FlowStep] | None:
        fn = self.ix.functions[key]
        args = _named(e.child_by_field_name("arguments"))
        site = self.facts(key).by_node.get((e.start_byte, e.end_byte))
        if site is None:
            return None
        line, col = _pos(e)
        if site.reason == "type conversion" and len(args) == 1:
            return self._taint(args[0], seed, key, seen, sdepth)
        if site.resolution == "propagator" and ret_index == 0:
            idx = range(len(args)) if site.prop_args is None else site.prop_args
            for i in idx:
                if i < len(args):
                    r = self._taint(args[i], seed, key, seen, sdepth)
                    if r is not None:
                        return r + [FlowStep(fn.file, line, col, fn.display, "propagate",
                                             f"{site.callee_text}(arg {i}) result")]
            return None
        if site.resolution != "resolved" or sdepth >= SUMMARY_DEPTH:
            return None
        callee = self.ix.functions[site.callee]
        for i, a in enumerate(args):
            j = self._callee_param(callee, i)
            if j is None:
                continue
            r = self._taint(a, seed, key, seen, sdepth)
            if r is None:
                continue
            inner = self._return_chain(site.callee, _Seed(callee.parameters[j].name, False), ret_index, sdepth + 1)
            if inner is not None:
                cp = callee.parameters[j]
                return r + [FlowStep(fn.file, line, col, fn.display, "summary_call", f"{site.callee_text}(arg {i})"),
                            FlowStep(callee.file, cp.line, cp.column, callee.display, "summary_param",
                                     f"param {j} ({cp.name})")] + inner
        if seed.request_vars and self.facts(site.callee).request_vars:
            inner = self._return_chain(site.callee, _Seed(None, True, self.facts(site.callee).request_vars),
                                       ret_index, sdepth + 1)
            if inner is not None:
                return inner + [FlowStep(fn.file, line, col, fn.display, "summary_call",
                                         f"{site.callee_text} result")]
        return None

    def _return_chain(self, key: str, seed: _Seed, ret_index: int, sdepth: int) -> list[FlowStep] | None:
        """How `seed` reaches result `ret_index` of function `key` (helper summaries)."""
        ck = (key, seed, ret_index)
        if ck in self._summaries:
            return self._summaries[ck]
        if ck in self._in_progress:
            return None
        self._in_progress.add(ck)
        fn = self.ix.functions[key]
        out = None
        for n in _walk(fn.body) if fn.body is not None else []:
            if n.type != "return_statement":
                continue
            exprs = _named(_named(n)[0]) if _named(n) and _named(n)[0].type == "expression_list" else _named(n)
            if len(exprs) > ret_index:
                r = self._taint(exprs[ret_index], seed, key, frozenset(), sdepth)
            elif len(exprs) == 1 and exprs[0].type == "call_expression":
                r = self._taint(exprs[0], seed, key, frozenset(), sdepth, ret_index)
            else:
                r = None
            if r is not None:
                line, col = _pos(n)
                out = r + [FlowStep(fn.file, line, col, fn.display, "return", f"result {ret_index}")]
                break
        self._in_progress.discard(ck)
        self._summaries[ck] = out
        return out

    @staticmethod
    def _callee_param(callee: GoFunction, arg_index: int) -> int | None:
        ps = callee.parameters
        if not ps:
            return None
        if arg_index >= len(ps) - 1 and ps[-1].variadic:
            idx = len(ps) - 1
        elif arg_index < len(ps):
            idx = arg_index
        else:
            return None
        return idx if ps[idx].name else None

    # ---- exploration
    def explore_param(self, key: str, pidx: int) -> None:
        p = self.ix.functions[key].parameters[pidx]
        if p.name is not None:
            self._explore(key, _Seed(p.name, True), 0, [key], [])

    def explore_http(self, key: str) -> None:
        reqs = self.facts(key).request_vars
        if reqs:
            self._explore(key, _Seed(None, True, reqs), 0, [key], [])

    def explore_operator(self, key: str) -> None:
        """DIAGNOSTIC ONLY (coverage measurement): operator flags / env as seeds."""
        self._explore(key, _Seed(None, True, operator=True), 0, [key], [])

    def _add_path(self, full: list[FlowStep], sink: FlowStep | None, depth: int, truncated: bool,
                  category: str | None, entry: str) -> None:
        k = (tuple((s.file, s.line, s.column, s.kind) for s in full),
             (sink.file, sink.line, sink.column, sink.detail) if sink else None)
        if k not in self._path_keys:
            self._path_keys.add(k)
            self.paths.append(FlowPath(full[0], full[1:], sink, depth, truncated, category, entry))

    def _entry(self, stack: list[str]) -> str:
        return self.ix.functions[stack[0]].display

    def _explore(self, key: str, seed: _Seed, depth: int, stack: list[str], prefix: list[FlowStep]) -> None:
        fn = self.ix.functions[key]
        facts = self.facts(key)
        for call in facts.calls:
            args = _named(call.node.child_by_field_name("arguments"))
            for ai, arg in enumerate(args):
                if len(self.paths) >= self.max_paths:
                    self.budget_exhausted = True
                    return
                chain = self._taint(arg, seed, key, frozenset(), 0)
                if chain is None:
                    continue
                full = prefix + chain
                if call.resolution == "sink":
                    positions = call.sink.positions(args)
                    if positions is None or ai in positions:
                        sink = FlowStep(call.file, call.line, call.column, fn.display, "sink_arg",
                                        f"{call.sink.label} arg {ai}")
                        self._add_path(full, sink, depth, False, call.sink.category, self._entry(stack))
                    else:
                        self.neutralized.append({"function": fn.display, "file": call.file, "line": call.line,
                                                 "call": call.callee_text, "arg": ai,
                                                 "reason": f"arg {ai} is not a sink position of {call.sink.label}"})
                    continue
                if call.resolution == "propagator":
                    continue                     # the flow continues through the call's result
                if call.resolution != "resolved":
                    self.tainted_no_proof.append({"function": fn.display, "file": call.file, "line": call.line,
                                                  "call": call.callee_text, "arg": ai, "reason": call.reason})
                    continue
                callee = self.ix.functions[call.callee]
                j = self._callee_param(callee, ai)
                if j is None:
                    continue
                cp = callee.parameters[j]
                hop = [FlowStep(call.file, call.line, call.column, fn.display, "call",
                                f"{call.callee_text}(arg {ai})"),
                       FlowStep(callee.file, cp.line, cp.column, callee.display, "param", f"param {j} ({cp.name})")]
                if call.callee in stack:
                    self.cycles.append([self.ix.functions[k].display for k in stack] + [callee.display])
                    continue
                if depth + 1 > self.max_depth:
                    self._add_path(full + hop, None, depth + 1, True, None, self._entry(stack))
                    continue
                self._explore(call.callee, _Seed(cp.name, False), depth + 1, stack + [call.callee], full + hop)
            self._explore_objects(key, call, args, seed, depth, stack, prefix)

    def _explore_objects(self, key: str, call: CallSite, args: list, seed: _Seed, depth: int, stack: list[str],
                         prefix: list[FlowStep]) -> None:
        """A struct object whose field carries the seed, passed as argument (x / &x) or used as receiver (x.M())."""
        fn = self.ix.functions[key]
        carriers: list[tuple[str, int | None, object]] = []        # (object var, arg index | None=receiver, node)
        for ai, arg in enumerate(args):
            var = self._object_arg(key, arg)
            if var:
                carriers.append((var, ai, arg))
        func = call.node.child_by_field_name("function")
        if func.type == "selector_expression" and func.child_by_field_name("operand").type == "identifier":
            var = self._object_arg(key, func.child_by_field_name("operand"))
            if var:
                carriers.append((var, None, call.node))
        for var, ai, node in carriers:
            typ = self._struct_of(key, var)[0]
            for fld in sorted(self.ix.types[typ].fields):
                if len(self.paths) >= self.max_paths:
                    self.budget_exhausted = True
                    return
                chain = self._field_taint(var, fld, node, seed, key, frozenset(), 0)
                if chain is None:
                    continue
                if call.resolution != "resolved":
                    if call.resolution != "sink":
                        self.tainted_no_proof.append({"function": fn.display, "file": call.file, "line": call.line,
                                                      "call": call.callee_text, "arg": ai,
                                                      "reason": f"object {var}.{fld}: {call.reason}"})
                    continue
                callee = self.ix.functions[call.callee]
                if ai is None:
                    if not callee.receiver_name:
                        continue
                    target, where = callee.receiver_name, (callee.file, callee.start_line, 1)
                    pdetail = f"receiver {target}.{fld}"
                else:
                    j = self._callee_param(callee, ai)
                    if j is None or callee.parameters[j].variadic:
                        continue
                    cp = callee.parameters[j]
                    if self.ix.resolve_type(cp.type_node, self.ix.fn_file[call.callee]) != typ:
                        self.tainted_no_proof.append({"function": fn.display, "file": call.file, "line": call.line,
                                                      "call": call.callee_text, "arg": ai,
                                                      "reason": f"object {var}.{fld} passed to a parameter of "
                                                                f"another/unknown type ({cp.type_text})"})
                        continue
                    target, where, pdetail = cp.name, (callee.file, cp.line, cp.column), f"param {j} ({cp.name}).{fld}"
                full = prefix + chain
                hop = [FlowStep(call.file, call.line, call.column, fn.display, "call",
                                f"{call.callee_text}({'receiver' if ai is None else f'arg {ai}'}: {var}.{fld})"),
                       FlowStep(where[0], where[1], where[2], callee.display, "param", pdetail)]
                if call.callee in stack:
                    self.cycles.append([self.ix.functions[k].display for k in stack] + [callee.display])
                    continue
                if depth + 1 > self.max_depth:
                    self._add_path(full + hop, None, depth + 1, True, None, self._entry(stack))
                    continue
                self._explore(call.callee, _Seed(target, False, field=fld), depth + 1, stack + [call.callee],
                              full + hop)


# --------------------------------------------------------------------------- public API

def _param_sources(fn: GoFunction, specs: list[str]) -> list[int]:
    if ALL_PARAMS in specs:
        return [p.index for p in fn.parameters]
    out: list[int] = []
    for s in specs:
        name, _, idx = s.partition("#")
        if name in (fn.display, fn.name):
            out += [p.index for p in fn.parameters] if not idx else [int(idx)] if int(idx) < len(fn.parameters) else []
    return sorted(set(out))


def analyze_go_repository(repo_path: str | Path, sinks: Iterable["str | SinkSpec"] = (),
                          sources: Iterable[str] = (), http_sources: bool = False,
                          max_depth: int = DEFAULT_MAX_DEPTH, include_tests: bool = False,
                          max_paths: int = MAX_PATHS, operator_sources: bool = False) -> AnalysisResult:
    """Statically analyse the `.go` files under `repo_path` (nothing is compiled or executed).

    sinks        : SinkSpec objects or strings ("name" / "import/path.Name"; every argument is a sink position).
    sources      : explicit parameter seeds: "Func", "Type.Method", "Func#<param index>", or "*" (all params).
                   A parameter is never a source unless listed here.
    http_sources : also seed request-derived expressions (HTTP_SOURCES) on `*net/http.Request` parameters.
    """
    root = Path(repo_path)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    ix = GoIndex(root, include_tests=include_tests)
    df = GoDataflow(ix, sinks=sinks, max_depth=max_depth, max_paths=max_paths)
    specs = [sources] if isinstance(sources, str) else list(sources)
    for key in sorted(ix.functions):
        for i in _param_sources(ix.functions[key], specs):
            df.explore_param(key, i)
        if http_sources:
            df.explore_http(key)
        if operator_sources:
            df.explore_operator(key)
    calls = [c for k in sorted(ix.functions) for c in df.facts(k).calls]
    return AnalysisResult(str(ix.root), sorted(ix.files), ix.functions, calls, df.paths,
                          _dedupe(df.tainted_no_proof), _dedupe(df.neutralized), df.cycles, ix.parse_errors,
                          ix.skipped, df.budget_exhausted, field_refusals=_dedupe(df.field_refusals),
                          pointer_refusals=_dedupe(df.pointer_refusals))


def analyze_security(repo_path: str | Path, max_depth: int = DEFAULT_MAX_DEPTH) -> AnalysisResult:
    """Preset used by the pipeline: HTTP request sources -> SECURITY_SINKS."""
    return analyze_go_repository(repo_path, sinks=SECURITY_SINKS, sources=(), http_sources=True,
                                 max_depth=max_depth)


def analyze_operator_diagnostics(repo_path: str | Path, max_depth: int = DEFAULT_MAX_DEPTH) -> AnalysisResult:
    """DIAGNOSTIC ONLY, never fed to the scanner: operator flags/env -> SECURITY_SINKS. Measures coverage;
    such paths are not user-input vulnerabilities without a separate justification."""
    return analyze_go_repository(repo_path, sinks=SECURITY_SINKS, sources=(), operator_sources=True,
                                 max_depth=max_depth)


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        k = tuple(sorted(it.items()))
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def format_path(path: FlowPath) -> str:
    lines = [f"{path.source.function}: {path.source.detail}  {path.source.file}:{path.source.line}"]
    for s in path.steps:
        if s.kind in ("param", "assign", "propagate", "return", "deref"):
            lines.append(f"  -> [{s.kind}] {s.function}: {s.detail}  {s.file}:{s.line}")
    if path.sink:
        lines.append(f"  -> [sink] {path.sink.detail}  {path.sink.file}:{path.sink.line}")
    if path.truncated:
        lines.append(f"  -> [truncated at depth {path.depth}]")
    return "\n".join(lines)


def path_to_evidence(path: FlowPath, extra: dict | None = None):
    """Potential evidence for evidence.py. Never above `moderate`: a syntactic path is not a proof of
    exploitability, and the decision engine requires SOURCE_TO_SINK >= strong to CONFIRM a code finding.
    Truncated paths yield nothing."""
    from .evidence import Evidence
    if path.truncated or path.sink is None:
        return None
    desc = " -> ".join(path.functions()) + f" -> {path.sink.detail}"
    return Evidence("SOURCE_TO_SINK", "static.go_dataflow", desc, EVIDENCE_MAX_STRENGTH, True, False, True,
                    "VERIFIED", {"go_dataflow_path": path.to_dict(), "engine": ENGINE_VERSION, **(extra or {})})
