"""Static validation steps. Nothing from the target repository is ever executed.

Each step reads files locally (or re-runs a static analyser, which parses but does not run code)
and returns a StepResult. Steps never store secret values.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..scanner.base import Scanner, ScannerError, ScanTarget
from . import gomod

# ----------------------------------------------------------------------------- types

@dataclass
class StepResult:
    validator: str
    outcome: str                 # CONFIRMED | FALSE_POSITIVE | INCONCLUSIVE (this step's own conclusion)
    signal: str                  # supports_real | supports_false_positive | neutral
    strength: str                # strong | weak
    details: str
    data: dict = field(default_factory=dict)
    duration_ms: int = 0


def _timed(fn: Callable[..., StepResult]) -> Callable[..., StepResult | None]:
    def wrap(*a, **kw):
        t0 = time.monotonic()
        res = fn(*a, **kw)
        if res is not None:
            res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
    wrap.__name__ = fn.__name__
    return wrap


# ----------------------------------------------------------------------------- 1. rule reproduction

@_timed
def rule_reproduction(repo: Path, finding: dict, scanners: dict[str, Scanner]) -> StepResult | None:
    """Re-run the producing scanner on the single file and check the same rule fires on the same line."""
    scanner = scanners.get(finding["scanner"])
    if finding["scanner"] in ("osv", "go_dataflow") or scanner is None:   # go_dataflow: static.go_dataflow
        return None
    if not scanner.available():
        return StepResult("static.rule_reproduction", "INCONCLUSIVE", "neutral", "weak",
                          f"{finding['scanner']} not available to reproduce")
    one = repo / finding["file"]
    if not one.is_file():
        return StepResult("static.rule_reproduction", "INCONCLUSIVE", "supports_false_positive", "weak",
                          "file no longer present in checkout", {"file": finding["file"]})
    try:
        tmp_target = ScanTarget(slug=finding.get("repository", "local"), path=repo, commit="revalidate")
        hits = [f for f in scanner.scan_file(tmp_target, finding["file"])
                if f.rule == finding["rule"] and f.line == finding["line"]]
    except (ScannerError, AttributeError) as e:
        return StepResult("static.rule_reproduction", "INCONCLUSIVE", "neutral", "weak",
                          f"reproduction failed: {e}")
    if hits:
        return StepResult("static.rule_reproduction", "INCONCLUSIVE", "supports_real", "weak",
                          f"rule {finding['rule']} reproduced at {finding['file']}:{finding['line']} "
                          "(deterministic static match, not a proof of exploitability)",
                          {"reproduced": True})
    return StepResult("static.rule_reproduction", "INCONCLUSIVE", "supports_false_positive", "weak",
                      "rule did not fire again on this file/line", {"reproduced": False})


# ----------------------------------------------------------------------------- 2. non-production code

_NONPROD = re.compile(
    r"(^|/)(tests?|testing|testdata|test_data|__tests__|spec|specs|e2e|fixtures?|mocks?|examples?|samples?|"
    r"demos?|docs?|benchmarks?|hack/testdata)(/|$)"
    r"|(^|/)test_[^/]*\.py$|_test\.(go|py)$|\.(spec|test)\.(js|jsx|ts|tsx)$|(^|/)conftest\.py$",
    re.I)


@_timed
def non_production_path(repo: Path, finding: dict, **_) -> StepResult:
    rel = finding["file"]
    m = _NONPROD.search(rel)
    if not m:
        return StepResult("static.non_production_path", "INCONCLUSIVE", "neutral", "weak",
                          "file is not in a test/example/testdata location", {"non_production": False})
    if finding["category"] == "vulnerable-dependency":
        # a manifest under examples/ or testdata/ is not shipped => FP for the project itself
        return StepResult("static.non_production_path", "FALSE_POSITIVE", "supports_false_positive", "strong",
                          f"dependency manifest in non-production path ({m.group(0).strip('/')})",
                          {"non_production": True, "match": m.group(0)})
    return StepResult("static.non_production_path", "FALSE_POSITIVE", "supports_false_positive", "strong",
                      f"code lives in non-production path ({m.group(0).strip('/')}); not reachable in a deployed build",
                      {"non_production": True, "match": m.group(0)})


# ----------------------------------------------------------------------------- 3. secret analysis

_PROVIDER_FORMATS = {
    "github_token": re.compile(r"^gh[pousr]_[A-Za-z0-9]{36}$"),
    "github_fine_grained": re.compile(r"^github_pat_[A-Za-z0-9_]{82}$"),
    "aws_access_key_id": re.compile(r"^(AKIA|ASIA)[0-9A-Z]{16}$"),
    "slack_token": re.compile(r"^xox[baprs]-[A-Za-z0-9-]{10,}$"),
    "stripe_live": re.compile(r"^(sk|rk)_live_[A-Za-z0-9]{20,}$"),
    "anthropic": re.compile(r"^sk-ant-[A-Za-z0-9_-]{40,}$"),
    "google_api_key": re.compile(r"^AIza[0-9A-Za-z_-]{35}$"),
}
_PLACEHOLDER = re.compile(
    r"example|sample|dummy|fake|placeholder|changeme|change_me|replace|your[_-]?|xxxx|\*\*\*\*|redacted|"
    r"<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\(?\w*\)?s|^\$\w+$|todo|insert|secret_here|notreal|test(ing)?[_-]?key",
    re.I)
_ENV_REF = re.compile(r"os\.environ|getenv|process\.env|ENV\[|System\.getenv|viper\.|secretKeyRef", re.I)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _candidate_values(line: str) -> list[str]:
    vals = re.findall(r"""["'`]([^"'`\n]{8,})["'`]""", line)
    m = re.search(r"""[:=]\s*([^\s"'`,;]{8,})""", line)
    if m:
        vals.append(m.group(1))
    return sorted(set(vals), key=len, reverse=True)


def _is_trivial(v: str) -> bool:
    return len(set(v)) <= 3 or v.lower() in ("abcdefghijklmnop", "1234567890123456") or \
        bool(re.fullmatch(r"(.)\1{7,}|0123456789.*|abcdef.*", v, re.I))


@_timed
def secret_analysis(repo: Path, finding: dict, **_) -> StepResult | None:
    """Classify a committed credential WITHOUT ever storing or using its value.
    Liveness is never tested (policy: never use credentials found in repositories)."""
    if finding["category"] != "secret":
        return None
    try:
        lines = (repo / finding["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return StepResult("static.secret_analysis", "INCONCLUSIVE", "neutral", "weak", "file unreadable")
    start, end = int(finding["line"]), int(finding.get("end_line") or finding["line"])
    block = "\n".join(lines[max(0, start - 1):end])
    if _PRIVATE_KEY.search(block) or (start <= len(lines) and _PRIVATE_KEY.search(lines[start - 1])):
        body = "\n".join(lines[start - 1:start + 40])
        enc = "ENCRYPTED" in body
        return StepResult("static.secret_analysis", "INCONCLUSIVE" if enc else "CONFIRMED",
                          "supports_real", "weak" if enc else "strong",
                          "PEM private key block committed" + (" (encrypted)" if enc else ""),
                          {"kind": "private_key", "encrypted": enc})
    values = [v for l in block.splitlines() for v in _candidate_values(l)]
    if not values:
        return StepResult("static.secret_analysis", "INCONCLUSIVE", "neutral", "weak",
                          "could not isolate the value on the reported line")
    v = values[0]
    facts = {"length": len(v), "entropy": round(shannon_entropy(v), 2), "provider_format": None,
             "placeholder": False, "env_reference": bool(_ENV_REF.search(block))}
    if facts["env_reference"]:
        return StepResult("static.secret_analysis", "FALSE_POSITIVE", "supports_false_positive", "strong",
                          "value is read from the environment / secret store, not hard-coded", facts)
    if _PLACEHOLDER.search(v) or _is_trivial(v):
        facts["placeholder"] = True
        return StepResult("static.secret_analysis", "FALSE_POSITIVE", "supports_false_positive", "strong",
                          "value looks like a placeholder / documentation sample", facts)
    for kind, rx in _PROVIDER_FORMATS.items():
        if rx.match(v):
            facts["provider_format"] = kind
            break
    if facts["provider_format"] and facts["entropy"] >= 3.5:
        return StepResult("static.secret_analysis", "CONFIRMED", "supports_real", "strong",
                          f"hard-coded value matches {facts['provider_format']} format with high entropy "
                          "(static evidence only; liveness deliberately NOT tested)", facts)
    if facts["entropy"] >= 4.0 and len(v) >= 20:
        return StepResult("static.secret_analysis", "INCONCLUSIVE", "supports_real", "weak",
                          "high-entropy hard-coded string of unknown provider", facts)
    return StepResult("static.secret_analysis", "INCONCLUSIVE", "supports_false_positive", "weak",
                      "low-entropy / short value, probably not a real credential", facts)


# ----------------------------------------------------------------------------- 4. dependency usage

_PY_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"], "pillow": ["PIL"], "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"], "opencv-python": ["cv2"], "protobuf": ["google.protobuf"],
    "attrs": ["attr", "attrs"], "pyjwt": ["jwt"], "pycryptodome": ["Crypto"], "pyopenssl": ["OpenSSL"],
    "python-jose": ["jose"], "msgpack-python": ["msgpack"], "djangorestframework": ["rest_framework"],
}
_SKIP = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build", "third_party"}
_EXT = {"PyPI": {".py"}, "npm": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}, "Go": {".go"},
        "crates.io": {".rs"}}


def _usage_patterns(eco: str, name: str) -> list[re.Pattern]:
    if eco == "PyPI":
        mods = _PY_IMPORT_NAMES.get(name, [name.replace("-", "_")])
        return [re.compile(rf"^\s*(from\s+{re.escape(m)}(\.|\s)|import\s+([\w.]+\s*,\s*)*{re.escape(m)}\b)",
                           re.M | re.I) for m in mods]
    if eco == "npm":
        n = re.escape(name)
        return [re.compile(rf"""(require\(\s*['"]{n}(/[^'"]*)?['"]\s*\)|from\s+['"]{n}(/[^'"]*)?['"]|"""
                           rf"""import\(\s*['"]{n}(/[^'"]*)?['"]\s*\))""")]
    if eco == "Go":
        return [re.compile(rf'"{re.escape(name)}(/[^"]*)?"')]
    if eco == "crates.io":
        return [re.compile(rf"\b{re.escape(name.replace('-', '_'))}::")]
    return []


@_timed
def dependency_usage(repo: Path, finding: dict, **_) -> StepResult | None:
    if finding["category"] != "vulnerable-dependency":
        return None
    m = re.match(r"([^:]+):(.+)==(.+)$", finding.get("evidence") or "")
    if not m:
        return StepResult("static.dependency_usage", "INCONCLUSIVE", "neutral", "weak", "unparseable evidence")
    eco, name, ver = m.groups()
    pats = _usage_patterns(eco, name)
    if not pats:
        return StepResult("static.dependency_usage", "INCONCLUSIVE", "neutral", "weak",
                          f"usage check not implemented for {eco}")
    if eco == "Go" and finding["file"].endswith("go.mod") and (repo / finding["file"]).is_file():
        return _go_dependency_usage(repo, finding, name, ver)
    manifest = (repo / finding["file"]).read_text(errors="replace") if (repo / finding["file"]).is_file() else ""
    indirect = bool(re.search(rf"{re.escape(name)}\s+\S+\s+//\s*indirect", manifest)) if eco == "Go" else None
    users: list[str] = []
    scope = (repo / finding["file"]).parent          # a manifest only governs its own subtree
    for p in scope.rglob("*"):
        rel = p.relative_to(repo)
        if p.suffix not in _EXT[eco] or not p.is_file() or p.is_symlink() or any(x in _SKIP for x in rel.parts):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(rx.search(text) for rx in pats):
            users.append(str(rel))
            if len(users) >= 20:
                break
    prod_users = [u for u in users if not _NONPROD.search(u)]
    facts = {"ecosystem": eco, "package": name, "version": ver, "importing_files": users[:20],
             "search_scope": str(scope.relative_to(repo)) or ".",
             "production_importers": len(prod_users), "go_indirect": indirect}
    if prod_users:
        return StepResult("static.dependency_usage", "INCONCLUSIVE", "supports_real", "weak",
                          f"{name} is imported by {len(prod_users)} production file(s); whether the vulnerable "
                          "function is reached is NOT established", facts)
    if users:
        return StepResult("static.dependency_usage", "INCONCLUSIVE", "supports_false_positive", "weak",
                          f"{name} only imported from test/example code", facts)
    return StepResult("static.dependency_usage", "INCONCLUSIVE", "supports_false_positive", "weak",
                      f"no direct import of {name} found (may still be a transitive/runtime dependency)", facts)


# ----------------------------------------------------------------------------- 4b. Go module relations

def _go_dependency_usage(repo: Path, finding: dict, name: str, ver: str) -> StepResult:
    """Relation of a vulnerable module to the Go module whose go.mod lists it.

    relation (first match):
      imported            imported by non-test, non-tooling code of this module   -> supports (moderate)
      tooling_pin         only blank-imported by a tools.go-style file              -> supports (weak)
      test_only           only imported by _test.go files                           -> contradicts (weak)
      direct_unused       direct requirement, never imported                        -> contradicts (weak)
      transitive_compiled not imported, but vendor/modules.txt compiles packages    -> supports (weak)
      transitive          indirect, module content hash in go.sum (in build graph)   -> neutral
      graph_only          only the go.mod hash in go.sum (code not needed to build) -> contradicts (weak)
      unknown             indirect, no go.sum/vendor information                    -> neutral
    "Not directly imported" is never, by itself, evidence of safety for an indirect dependency.
    """
    gm = gomod.parse_go_mod(repo / finding["file"])
    req = gm.requires.get(name)
    files = gomod.module_go_files(repo, gm.dir)
    prod, tests, pins = [], [], []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not any(gomod.path_in_module(ip, name) for ip, _ in gomod.imports(text)):
            continue
        rel = str(p.relative_to(repo))
        if p.name.endswith("_test.go") or _NONPROD.search(rel):
            tests.append(rel)
        elif gomod.is_tooling_pin_file(text):
            pins.append(rel)
        else:
            prod.append(rel)
    sums = gomod.gosum_entries(gm.dir).get(f"{name}@{ver}", {})
    vendored = gomod.vendor_packages(gm.dir).get(name, [])
    facts = {"ecosystem": "Go", "package": name, "version": ver, "module": gm.module,
             "module_dir": str(gm.dir.relative_to(repo)) or ".",
             "requirement": "absent" if req is None else ("indirect" if req[1] else "direct"),
             "production_importers": prod[:20], "tooling_pin_importers": pins[:20], "test_importers": tests[:20],
             "go_sum": sums, "vendored_packages": vendored[:20]}

    def r(relation, signal, strength, details):
        facts["relation"] = relation
        return StepResult("static.dependency_usage", "INCONCLUSIVE", signal, strength, details, facts)

    if prod:
        return r("imported", "supports_real", "weak",
                 f"{name} is imported by {len(prod)} file(s) of module {gm.module}; reachability of the vulnerable "
                 "symbols is NOT established")
    if pins:
        return r("tooling_pin", "supports_real", "weak", f"{name} is only blank-imported by tooling pin file(s)")
    if tests:
        return r("test_only", "supports_false_positive", "weak", f"{name} only imported from test code")
    if req is not None and not req[1]:
        return r("direct_unused", "supports_false_positive", "weak",
                 f"{name} is a direct requirement of {gm.module} but no file of the module imports it")
    if vendored:
        return r("transitive_compiled", "supports_real", "weak",
                 f"{name} not imported directly but {len(vendored)} of its packages are vendored (compiled) "
                 "for this module")
    if sums.get("zip"):
        return r("transitive", "neutral", "weak",
                 f"{name} is a transitive dependency in the build graph of {gm.module} (content hash in go.sum); "
                 "not imported directly - this is NOT evidence of safety")
    if sums.get("mod"):
        return r("graph_only", "supports_false_positive", "weak",
                 f"go.sum lists only the go.mod hash of {name}@{ver}: its code is not needed to build {gm.module}")
    return r("unknown", "neutral", "weak", f"{name} is an indirect dependency; no go.sum/vendor data to place it")


# ----------------------------------------------------------------------------- 5. build-only Go module

_DOCKERFILE = re.compile(r"(^|/)(Dockerfile[^/]*|Containerfile[^/]*|[^/]*\.dockerfile)$", re.I)


@_timed
def build_only_module(repo: Path, finding: dict, **_) -> StepResult | None:
    """Is the go.mod that carries this vulnerable dependency a separate, build-tooling-only module?

    STRONG (FALSE_POSITIVE) only when ALL hold, each verified from local files:
      c1 separate_module      a different Go module exists at an ancestor directory (the product module)
      c2 tooling_files_only   every .go file of this module is a tools.go-style pin (build tag `tools`
                              or blank imports only), and there is at least one
      c3 not_used_by_product  the product module neither imports nor requires/replaces this module
      c4 dep_absent_from_product_graph  the vulnerable module is absent from the product's go.mod,
                              go.sum and vendor/modules.txt
      c5 not_in_images        no Dockerfile/Containerfile references this module's directory
    Otherwise -> INCONCLUSIVE/neutral with the list of unmet criteria (no evidence is produced).
    """
    if finding["category"] != "vulnerable-dependency" or not finding["file"].endswith("go.mod"):
        return None
    m = re.match(r"Go:(.+)==(.+)$", finding.get("evidence") or "")
    if not m or not (repo / finding["file"]).is_file():
        return None
    name = m.group(1)
    gm = gomod.parse_go_mod(repo / finding["file"])
    rel_dir = str(gm.dir.relative_to(repo)) or "."
    product_dirs = [d for d in gomod.module_dirs(repo) if d != gm.dir and d in gm.dir.parents]
    crit: dict[str, bool] = {}
    facts: dict = {"module": gm.module, "module_dir": rel_dir}

    product = gomod.parse_go_mod(product_dirs[-1] / "go.mod") if product_dirs else None   # nearest ancestor
    crit["c1_separate_module"] = bool(product and product.module and product.module != gm.module)
    files = gomod.module_go_files(repo, gm.dir)
    texts = {}
    for p in files:
        try:
            texts[str(p.relative_to(repo))] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            texts[str(p.relative_to(repo))] = ""
    non_pin = [f for f, t in texts.items() if not gomod.is_tooling_pin_file(t)]
    crit["c2_tooling_files_only"] = bool(texts) and not non_pin
    facts.update(module_files=sorted(texts)[:20], non_tooling_files=non_pin[:20])
    if product:
        facts["product_module"] = product.module
        prod_files = gomod.module_go_files(repo, product.dir)
        uses = [str(p.relative_to(repo)) for p in prod_files
                if any(gomod.path_in_module(ip, gm.module) for ip, _ in gomod.imports(p.read_text(errors="replace")))]
        crit["c3_not_used_by_product"] = (not uses and gm.module not in product.requires
                                          and gm.module not in product.replaces)
        facts["product_files_importing_module"] = uses[:10]
        in_req = name in product.requires
        in_sum = any(k.startswith(name + "@") for k in gomod.gosum_entries(product.dir))
        in_vendor = name in gomod.vendor_packages(product.dir)
        crit["c4_dep_absent_from_product_graph"] = not (in_req or in_sum or in_vendor)
        facts["vulnerable_module_in_product"] = {"go.mod": in_req, "go.sum": in_sum, "vendor": in_vendor}
    else:
        crit["c3_not_used_by_product"] = crit["c4_dep_absent_from_product_graph"] = False
    refs = []
    for p in repo.rglob("*"):
        r_ = str(p.relative_to(repo))
        if _DOCKERFILE.search(r_) and p.is_file() and not any(x in _SKIP for x in p.relative_to(repo).parts):
            t = p.read_text(errors="replace")
            if rel_dir != "." and re.search(rf"(^|[\s/\"'.]){re.escape(rel_dir)}(/|\s|$)", t, re.M):
                refs.append(r_)
    crit["c5_not_in_images"] = not refs
    facts["dockerfiles_referencing_module"] = refs
    # supporting signal only (recorded, not required): build scripts use the module as tooling
    scripts = []
    for cand in ("Makefile", "makefile", "GNUmakefile", "build.sh", "hack"):
        for p in ([repo / cand] if (repo / cand).is_file() else list((repo / cand).rglob("*.sh")) if (repo / cand).is_dir() else []):
            if re.search(rf"(pushd|cd|-C|-modfile[= ])\s*\.?/?{re.escape(rel_dir)}\b", p.read_text(errors="replace")):
                scripts.append(str(p.relative_to(repo)))
    facts["build_scripts_using_module_as_tooling"] = scripts
    facts["criteria"] = crit
    unmet = [k for k, v in crit.items() if not v]
    if not unmet:
        return StepResult("static.build_only_module", "FALSE_POSITIVE", "supports_false_positive", "strong",
                          f"{name} is only in the separate build-tooling module {gm.module} ({rel_dir}/go.mod): "
                          f"all criteria c1-c5 verified locally; not part of product module {product.module}", facts)
    return StepResult("static.build_only_module", "INCONCLUSIVE", "neutral", "weak",
                      f"cannot establish that {rel_dir}/go.mod is build-only; unmet: {', '.join(unmet)}", facts)


# ----------------------------------------------------------------------------- 6. Go inter-procedural path

_GO_CODE_CATEGORIES = ("command-injection", "sql-injection", "path-traversal", "ssrf")
_GO_CACHE: dict[tuple, object] = {}


def _go_analysis(repo: Path):
    """Security-preset analysis of the checkout, cached per repo state (path + .go files' mtimes/sizes)."""
    from ..analysis import go_dataflow as gd
    root = repo.resolve()
    sig = tuple(sorted((str(p.relative_to(root)), p.stat().st_mtime_ns, p.stat().st_size)
                       for p in root.rglob("*.go") if p.is_file() and not p.is_symlink()))
    key = (str(root), hash(sig))
    if key not in _GO_CACHE:
        _GO_CACHE.clear()
        _GO_CACHE[key] = gd.analyze_security(root)
    return _GO_CACHE[key]


@_timed
def go_dataflow_path(repo: Path, finding: dict, **_) -> StepResult | None:
    """Re-establish (go_dataflow findings) or look for (Semgrep Go findings) a resolved HTTP-source -> sink
    path ending at the finding's line. Static only; a path is a potential flow, not a proof."""
    from ..analysis import go_dataflow as gd
    own = finding.get("scanner") == "go_dataflow"
    if not own and not (str(finding.get("file", "")).endswith(".go") and finding.get("scanner") == "semgrep"
                        and finding.get("category") in _GO_CODE_CATEGORIES):
        return None
    if not gd.available():
        return StepResult("static.go_dataflow", "INCONCLUSIVE", "neutral", "weak", "tree-sitter-go not installed")
    res = _go_analysis(repo)
    paths = [p for p in res.paths if not p.truncated and p.sink is not None and p.sink.file == finding["file"]
             and p.sink.line == int(finding["line"]) and p.category == finding.get("category")]
    refusals = [n for n in res.tainted_no_proof if n["file"] == finding["file"]]
    data = {"engine": res.engine, "path_count": len(paths), "paths": [p.to_dict() for p in paths[:5]],
            "refused_calls_in_file": refusals[:10], "status": gd.PATH_STATUS}
    if paths:
        p = paths[0]
        return StepResult("static.go_dataflow", "INCONCLUSIVE", "supports_real", "weak",
                          f"resolved static path ({p.depth} hop(s), files: {', '.join(p.files())}): "
                          f"{p.source.detail} -> {' -> '.join(p.functions())} -> {p.sink.detail}. "
                          "Potential flow: sanitisation/authorization not modelled, not a proof of exploitability",
                          data)
    if own:
        return StepResult("static.go_dataflow", "INCONCLUSIVE", "supports_false_positive", "weak",
                          "path no longer reproduced on this checkout", data)
    return StepResult("static.go_dataflow", "INCONCLUSIVE", "neutral", "weak",
                      "no resolved HTTP-source path to this line (absence is not evidence of safety)", data)


def run_static_steps(repo: Path, finding: dict, scanners: dict[str, Scanner]) -> list[StepResult]:
    steps = [non_production_path(repo, finding),
             rule_reproduction(repo, finding, scanners),
             go_dataflow_path(repo, finding),
             secret_analysis(repo, finding),
             dependency_usage(repo, finding),
             build_only_module(repo, finding)]
    return [s for s in steps if s is not None]
