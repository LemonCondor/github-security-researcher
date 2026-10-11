"""Static Go module facts (parsing only; nothing is executed, no `go` toolchain needed).

Used by dependency_usage (direct / indirect / imported / transitive / graph-only) and by
build_only_module (is a module pure build tooling, separate from the shipped product?).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {".git", "vendor", "testdata", "node_modules", "third_party"}


@dataclass
class GoMod:
    dir: Path
    module: str
    requires: dict[str, tuple[str, bool]] = field(default_factory=dict)   # path -> (version, indirect)
    replaces: dict[str, str] = field(default_factory=dict)


def parse_go_mod(path: Path) -> GoMod:
    text = path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^\s*module\s+(\S+)", text, re.M)
    gm = GoMod(dir=path.parent, module=(m.group(1).strip('"') if m else ""))
    in_req = in_rep = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_req = True; continue
        if line.startswith("replace ("):
            in_rep = True; continue
        if line == ")":
            in_req = in_rep = False; continue
        if line.startswith("require "):
            _add_req(gm, line[len("require "):])
        elif in_req:
            _add_req(gm, line)
        elif line.startswith("replace ") or in_rep:
            body = line[len("replace "):] if line.startswith("replace ") else line
            if "=>" in body:
                left, right = body.split("=>", 1)
                gm.replaces[left.split()[0]] = right.strip()
    return gm


def _add_req(gm: GoMod, line: str) -> None:
    parts = line.split("//", 1)
    toks = parts[0].split()
    if len(toks) >= 2:
        gm.requires[toks[0]] = (toks[1], len(parts) > 1 and "indirect" in parts[1])


def module_dirs(repo: Path) -> list[Path]:
    out = []
    for p in repo.rglob("go.mod"):
        rel = p.relative_to(repo)
        if not any(x in _SKIP_DIRS for x in rel.parts[:-1]) and p.is_file() and not p.is_symlink():
            out.append(p.parent)
    return sorted(out)


def module_go_files(repo: Path, mod_dir: Path) -> list[Path]:
    """Go files belonging to the module rooted at mod_dir (nested modules excluded)."""
    nested = [d for d in module_dirs(repo) if d != mod_dir and mod_dir in d.parents]
    files = []
    for p in mod_dir.rglob("*.go"):
        rel = p.relative_to(mod_dir)
        if any(x in _SKIP_DIRS or x.startswith(".") for x in rel.parts[:-1]):
            continue
        if any(n == p.parent or n in p.parents for n in nested) or p.is_symlink() or not p.is_file():
            continue
        files.append(p)
    return sorted(files)


_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)^\)", re.S | re.M)
_IMPORT_LINE = re.compile(r'^import\s+(?:[\w.]+\s+|_\s+)?"([^"]+)"', re.M)
_IMPORT_ITEM = re.compile(r'^\s*(?:([\w.]+)\s+)?"([^"]+)"', re.M)


def imports(text: str) -> list[tuple[str, str | None]]:
    """[(import_path, alias)] ; alias '_' marks a blank import."""
    out = [(m.group(1), None) for m in _IMPORT_LINE.finditer(text)]
    for blk in _IMPORT_BLOCK.finditer(text):
        for m in _IMPORT_ITEM.finditer(blk.group(1)):
            out.append((m.group(2), m.group(1)))
    blank = re.findall(r'^import\s+_\s+"([^"]+)"', text, re.M)
    return [(p, "_" if p in blank and a is None else a) for p, a in out]


_DECL = re.compile(r"^(func|type|var|const)\b", re.M)


def is_tooling_pin_file(text: str) -> bool:
    """`tools.go` pattern: build tag `tools`, or a file that only blank-imports packages."""
    if re.search(r"^//go:build\s+tools\b|^//\s*\+build\s+tools\b", text, re.M):
        return True
    imps = imports(text)
    return bool(imps) and all(a == "_" for _, a in imps) and not _DECL.search(text) \
        and not re.search(r"^package\s+main\b", text, re.M)


def gosum_entries(mod_dir: Path) -> dict[str, dict[str, bool]]:
    """module@version -> {"zip": has module-content hash, "mod": has go.mod hash}."""
    p = mod_dir / "go.sum"
    out: dict[str, dict[str, bool]] = {}
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        toks = line.split()
        if len(toks) < 3:
            continue
        mod, ver = toks[0], toks[1]
        is_mod = ver.endswith("/go.mod")
        key = f"{mod}@{ver[:-len('/go.mod')] if is_mod else ver}"
        e = out.setdefault(key, {"zip": False, "mod": False})
        e["mod" if is_mod else "zip"] = True
    return out


def vendor_packages(mod_dir: Path) -> dict[str, list[str]]:
    """module -> packages listed in vendor/modules.txt (= packages compiled from that module)."""
    p = mod_dir / "vendor" / "modules.txt"
    out: dict[str, list[str]] = {}
    cur = None
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        if line.startswith("# "):
            toks = line[2:].split()
            cur = toks[0] if toks else None
            if cur:
                out.setdefault(cur, [])
        elif line and not line.startswith("#") and cur:
            out[cur].append(line.strip())
    return out


def path_in_module(import_path: str, module: str) -> bool:
    return import_path == module or import_path.startswith(module + "/")
