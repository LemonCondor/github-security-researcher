"""Bounded, progressive context for one finding (never the whole repository).

Order: 1 file window -> 2 enclosing function -> 3 callers -> 4 callees -> 5 tests -> 6 dataflow metadata
-> 7 dependency info. Secret lines are masked before anything leaves the machine.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..security.secrets import redact

MAX_CHARS = 24_000
_LANG_EXT = {".py": "python", ".go": "go", ".js": "javascript", ".ts": "typescript", ".jsx": "javascript",
             ".tsx": "typescript", ".java": "java", ".rb": "ruby", ".php": "php", ".rs": "rust"}
_SKIP = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "third_party"}


@dataclass
class Snippet:
    kind: str           # file_window | function | caller | callee | test | dependency | dataflow_step
    file: str
    start: int
    end: int
    text: str           # numbered lines


@dataclass
class FindingContext:
    finding: dict
    snippets: list[Snippet] = field(default_factory=list)
    truncated: bool = False
    advisory: dict | None = None      # OSV advisory (external, untrusted data) for dependency findings
    dataflow: list[dict] | None = None  # go_dataflow path steps (locations computed locally; details = code text)

    def visible_lines(self) -> set[tuple[str, int]]:
        return {(s.file, n) for s in self.snippets for n in range(s.start, s.end + 1)}

    def sha256(self) -> str:
        h = hashlib.sha256(repr(sorted(self.finding.items())).encode())
        for s in self.snippets:
            h.update(f"{s.kind}|{s.file}|{s.start}|{s.end}|{s.text}".encode())
        if self.advisory:
            h.update(json.dumps(self.advisory, sort_keys=True).encode())
        if self.dataflow:
            h.update(json.dumps(self.dataflow, sort_keys=True).encode())
        return h.hexdigest()


def _lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _numbered(lines: list[str], start: int, end: int, masked: set[int]) -> str:
    out = []
    for n in range(start, end + 1):
        text = "[SECRET VALUE REDACTED]" if n in masked else redact(lines[n - 1])
        out.append(f"{n:>5} | {text[:400]}")
    return "\n".join(out)


def _python_enclosing(src: list[str], line: int):
    try:
        tree = ast.parse("\n".join(src))
    except (SyntaxError, ValueError):
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or 0):
            if best is None or node.lineno > best.lineno:
                best = node
    if best is None:
        return None
    start = min([d.lineno for d in best.decorator_list] + [best.lineno])
    callees = sorted({n.func.id for n in ast.walk(best) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)})
    return best.name, start, best.end_lineno, callees


_FUNC_HDR = {
    "go": re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "javascript": re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|"
                             r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\("),
}
_FUNC_HDR["typescript"] = _FUNC_HDR["javascript"]


def _brace_enclosing(src: list[str], line: int, lang: str):
    hdr = _FUNC_HDR.get(lang)
    if not hdr:
        return None
    for i in range(min(line, len(src)) - 1, max(-1, line - 400), -1):
        m = hdr.match(src[i])
        if m:
            name = next(g for g in m.groups() if g)
            depth, seen = 0, False
            for j in range(i, min(len(src), i + 400)):
                depth += src[j].count("{") - src[j].count("}")
                seen = seen or "{" in src[j]
                if seen and depth <= 0:
                    return (name, i + 1, j + 1, []) if j + 1 >= line else None
            return None
    return None


def _iter_code_files(root: Path, lang: str):
    exts = {e for e, l in _LANG_EXT.items() if l == lang}
    for p in root.rglob("*"):
        rel = p.relative_to(root)
        if p.suffix in exts and p.is_file() and not p.is_symlink() and not any(x in _SKIP for x in rel.parts):
            yield p, str(rel)


def build_context(repo: Path, finding: dict, masked_lines: dict[str, set[int]] | None = None,
                  max_chars: int = MAX_CHARS) -> FindingContext:
    """finding: dict with file, line, end_line, category, rule, scanner, source, sink, evidence..."""
    masked_lines = masked_lines or {}
    ctx = FindingContext(finding={k: finding.get(k) for k in (
        "id", "scanner", "rule", "category", "severity", "file", "line", "end_line", "source", "sink",
        "description", "evidence")})
    extra = finding.get("extra") or {}
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except ValueError:
            extra = {}
    if finding.get("category") == "vulnerable-dependency" and extra.get("advisory"):
        ctx.advisory = extra["advisory"]
    rel, line = finding["file"], int(finding["line"])
    path = repo / rel
    src = _lines(path)
    if not src:
        return ctx
    lang = _LANG_EXT.get(path.suffix)
    masked = masked_lines.get(rel, set())
    if finding.get("category") == "secret":
        masked |= set(range(line, int(finding.get("end_line") or line) + 1))
    budget = [max_chars]

    def add(kind, f, s, e, lines, m):
        s, e = max(1, s), min(len(lines), e)
        text = _numbered(lines, s, e, m)
        if len(text) > budget[0]:
            ctx.truncated = True
            return False
        budget[0] -= len(text)
        ctx.snippets.append(Snippet(kind, f, s, e, text))
        return True

    # 1. file window
    end = int(finding.get("end_line") or line)
    if not add("file_window", rel, line - 25, end + 25, src, masked):
        add("file_window", rel, line - 3, end + 3, src, masked)     # minimal fallback

    # 2. enclosing function
    enc = _python_enclosing(src, line) if lang == "python" else _brace_enclosing(src, line, lang or "")
    if enc:
        name, s, e, callees = enc
        win = ctx.snippets[0] if ctx.snippets else None
        if win and (s < win.start or e > win.end):
            add("function", rel, s, min(e, s + 150), src, masked)

        # 3. callers (same language, bounded)
        if lang and len(name) > 2 and name not in {"main", "init", "run", "get", "post"}:
            pat = re.compile(rf"\b{re.escape(name)}\s*\(")
            hits = 0
            for p, r in _iter_code_files(repo, lang):
                ls = _lines(p)
                for i, l in enumerate(ls, 1):
                    if pat.search(l) and not (r == rel and s <= i <= e) and not re.match(r"\s*(def|func)\s", l):
                        kind = "test" if re.search(r"(^|/)(tests?|spec)/|_test\.|test_", r) else "caller"
                        if add(kind, r, i - 5, i + 5, ls, masked_lines.get(r, set())):
                            hits += 1
                        break
                if hits >= 5:
                    break

        # 4. callees defined in the same file (python)
        if lang == "python":
            try:
                tree = ast.parse("\n".join(src))
                defs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
                for cname in [c for c in callees if c in defs and c != name][:3]:
                    d = defs[cname]
                    add("callee", rel, d.lineno, min(d.end_lineno or d.lineno, d.lineno + 40), src, masked)
            except SyntaxError:
                pass

    # 6. dataflow path (go_dataflow): every step's line is shown so that citations can be checked
    paths = (extra.get("go_dataflow") or {}).get("paths") or []
    if paths:
        _add_dataflow(ctx, repo, paths[0], add, masked_lines)
    return ctx


_DATAFLOW_KINDS = ("source_param", "source_expr", "source_operator", "assign", "propagate", "summary_call", "return", "call", "param",
                   "sink_arg")


def _add_dataflow(ctx: FindingContext, repo: Path, path: dict, add, masked_lines) -> None:
    steps = [path["source"], *path.get("steps", []), *([path["sink"]] if path.get("sink") else [])]
    steps = [s for s in steps if s.get("kind") in _DATAFLOW_KINDS]
    ctx.dataflow = [{k: s.get(k) for k in ("kind", "function", "file", "line", "detail")} for s in steps]
    shown = ctx.visible_lines()
    for s in steps[:16]:
        f, n = str(s.get("file")), int(s.get("line") or 0)
        if (f, n) in shown or ".." in Path(f).parts or Path(f).is_absolute():
            continue
        lines = _lines(repo / f)
        if lines and add("dataflow_step", f, n - 2, n + 2, lines, masked_lines.get(f, set())):
            shown |= {(f, i) for i in range(n - 2, n + 3)}
