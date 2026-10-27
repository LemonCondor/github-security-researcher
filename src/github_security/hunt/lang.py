"""Language detection and the exact commands used to run a repro or a test file (Python, Go, JS/TS)."""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..ai.reviewer import _env

EXTS = {"py": (".py",), "go": (".go",), "js": (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")}


@dataclass
class Toolchain:
    python: str = "python3"
    go: str = "go"
    node: str = "node"


def _source_counts(repo: Path) -> dict[str, int]:
    p = subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True)
    files = p.stdout.splitlines() if p.returncode == 0 else []
    return {lang: sum(f.endswith(exts) for f in files) for lang, exts in EXTS.items()}


def detect_lang(repo: Path) -> str:
    """Language of the repo's own code. Several markers (a Python project with a package.json for its docs or CDK)
    are settled by which language has the most tracked source files."""
    found = []
    if (repo / "go.mod").exists():
        found.append("go")
    if (repo / "package.json").exists():
        found.append("js")
    if any((repo / f).exists() for f in ("pyproject.toml", "setup.py", "setup.cfg")):
        found.append("py")
    if not found:
        raise ValueError(f"unsupported language in {repo}")
    if len(found) == 1:
        return found[0]
    counts = _source_counts(repo)
    return max(found, key=lambda lang: counts[lang])


def _pkg_dir(path: str) -> str:
    return "./" + str(Path(path).parent)


def repro_cmd(lang: str, repro_path: str, tc: Toolchain) -> list[str]:
    if lang == "py":
        return [tc.python, repro_path]
    if lang == "go":
        return [tc.go, "test", "-count=1", "-run", "TestGsrRepro", _pkg_dir(repro_path)]
    return [tc.node, repro_path]


def _js_runner(repo: Path) -> str:
    try:
        pkg = json.loads((repo / "package.json").read_text())
    except (OSError, ValueError):
        return "node"
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    return "vitest" if "vitest" in deps else "jest" if "jest" in deps else "node"


def test_cmd(lang: str, test_file: str, repo: Path, tc: Toolchain) -> list[str]:
    if lang == "py":
        return [tc.python, "-m", "pytest", "-q", "-p", "no:cacheprovider", test_file]
    if lang == "go":
        return [tc.go, "test", "-count=1", _pkg_dir(test_file)]
    runner = _js_runner(repo)
    if runner == "vitest":
        return ["npx", "vitest", "run", test_file]
    if runner == "jest":
        return ["npx", "jest", test_file]
    return [tc.node, "--test", test_file]


def py_path_env(cwd: Path) -> dict:
    """PYTHONPATH putting the worktree (src/ first) ahead of any editable install of the main checkout."""
    parts = [str(p) for p in (cwd / "src", cwd) if p.is_dir()]
    if os.environ.get("PYTHONPATH"):
        parts.append(os.environ["PYTHONPATH"])
    return {"PYTHONPATH": ":".join(parts)}


def run(cmd: list[str], cwd: Path, timeout: int = 600) -> tuple[int, str]:
    """Run target code (untrusted) inside its worktree, without credentials. 124 = timeout."""
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env={**_env(), **py_path_env(cwd)})
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, str(e)
    return p.returncode, (p.stdout + p.stderr)[-4000:]


test_cmd.__test__ = False  # not a pytest test: keeps the required name when imported into test modules
