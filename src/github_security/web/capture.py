"""Offline capture loading for the passive web engine.

Inputs are DATA ONLY (never executed, never fetched):
  * raw HTTP response files (``*.http`` / ``*.resp``): optional ``# url: ...`` / ``# request-header: Name: value`` /
    ``# method: GET`` comment lines, then the status line, headers, blank line, body;
  * JSON captures (``*.json`` with ``"format": "web-capture/1"``): an ordered list of request/response exchanges,
    which is how redirect chains and request headers (Origin) are modelled;
  * standalone resources (``*.html``, ``*.htm``, ``*.js``, ``*.mjs``): body-only checks.

This module performs no network I/O and resolves no hostnames.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

CAPTURE_FORMAT = "web-capture/1"
MAX_FILE_BYTES = 5 * 1024 * 1024          # bigger inputs are truncated (body checks are bounded)
MAX_FILES = 2000
RAW_SUFFIXES = {".http", ".resp"}
RESOURCE_SUFFIXES = {".html", ".htm", ".js", ".mjs"}


class CaptureError(ValueError):
    """Malformed capture input."""


@dataclass
class Headers:
    items: list[tuple[str, str]] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.items if k.lower() == n]

    def get(self, name: str) -> str | None:
        vals = self.get_all(name)
        return vals[0] if vals else None

    def has(self, name: str) -> bool:
        return bool(self.get_all(name))


@dataclass
class Exchange:
    url: str                       # request URL ("" when unknown)
    method: str
    request_headers: Headers
    status: int | None             # None for standalone resources
    headers: Headers
    body: str
    source: str                    # input file (+ #index for JSON captures)
    index: int = 0
    kind: str = "http"             # "http" | "resource"

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower() if self.url else ""

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower() if self.url else ""

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()

    def is_html(self) -> bool:
        if self.content_type:
            return self.content_type in ("text/html", "application/xhtml+xml")
        head = self.body.lstrip()[:200].lower()
        return head.startswith("<!doctype html") or head.startswith("<html")

    def is_js(self) -> bool:
        ct = self.content_type
        if ct:
            return "javascript" in ct or ct == "application/ecmascript"
        return urlsplit(self.url).path.lower().endswith((".js", ".mjs"))


def _read_text(path: Path) -> str:
    with path.open("rb") as fh:
        data = fh.read(MAX_FILE_BYTES)
    return data.decode("utf-8", errors="replace")


def _parse_header_lines(lines: list[str], source: str) -> Headers:
    items: list[tuple[str, str]] = []
    for ln in lines:
        if not ln.strip():
            continue
        if ln[:1] in " \t" and items:          # obsolete line folding
            k, v = items[-1]
            items[-1] = (k, v + " " + ln.strip())
            continue
        if ":" not in ln:
            raise CaptureError(f"{source}: malformed header line {ln[:60]!r}")
        k, v = ln.split(":", 1)
        items.append((k.strip(), v.strip()))
    return Headers(items)


def parse_raw_response(text: str, source: str) -> Exchange:
    text = text.replace("\r\n", "\n")
    lines = text.split("\n")
    url, method, req_items = "", "GET", []
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        meta = lines[i][1:].strip()
        low = meta.lower()
        if low.startswith("url:"):
            url = meta[4:].strip()
        elif low.startswith("method:"):
            method = meta[7:].strip().upper() or "GET"
        elif low.startswith("request-header:"):
            req_items.append(meta[len("request-header:"):].strip())
        i += 1
    if i >= len(lines) or not lines[i].upper().startswith("HTTP/"):
        raise CaptureError(f"{source}: missing HTTP status line")
    parts = lines[i].split(None, 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError) as exc:
        raise CaptureError(f"{source}: bad status line {lines[i][:60]!r}") from exc
    i += 1
    hdr_lines = []
    while i < len(lines) and lines[i].strip():
        hdr_lines.append(lines[i])
        i += 1
    body = "\n".join(lines[i + 1:])
    return Exchange(url=url, method=method, request_headers=_parse_header_lines(req_items, source),
                    status=status, headers=_parse_header_lines(hdr_lines, source), body=body, source=source)


def _headers_from_json(obj, source: str) -> Headers:
    if obj is None:
        return Headers()
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            for one in (v if isinstance(v, list) else [v]):
                items.append((str(k), str(one)))
        return Headers(items)
    if isinstance(obj, list):
        out = []
        for pair in obj:
            if not (isinstance(pair, (list, tuple)) and len(pair) == 2):
                raise CaptureError(f"{source}: headers list must contain [name, value] pairs")
            out.append((str(pair[0]), str(pair[1])))
        return Headers(out)
    raise CaptureError(f"{source}: headers must be an object or a list of pairs")


def parse_json_capture(text: str, source: str, base_dir: Path) -> list[Exchange]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CaptureError(f"{source}: invalid JSON ({exc.msg})") from exc
    if not isinstance(doc, dict) or doc.get("format") != CAPTURE_FORMAT:
        raise CaptureError(f"{source}: not a {CAPTURE_FORMAT} capture")
    out = []
    for idx, ex in enumerate(doc.get("exchanges") or []):
        req, resp = ex.get("request") or {}, ex.get("response") or {}
        body = resp.get("body", "")
        if "body_file" in resp:                       # relative to the capture, no traversal
            bf = (base_dir / str(resp["body_file"])).resolve()
            if base_dir.resolve() not in bf.parents or not bf.is_file():
                raise CaptureError(f"{source}#{idx}: body_file outside capture directory or missing")
            body = _read_text(bf)
        try:
            status = int(resp.get("status"))
        except (TypeError, ValueError) as exc:
            raise CaptureError(f"{source}#{idx}: response.status is required") from exc
        out.append(Exchange(url=str(req.get("url", "")), method=str(req.get("method", "GET")).upper(),
                            request_headers=_headers_from_json(req.get("headers"), source), status=status,
                            headers=_headers_from_json(resp.get("headers"), source), body=str(body),
                            source=f"{source}#{idx}", index=idx))
    return out


def load_resource(path: Path, source: str) -> Exchange:
    return Exchange(url=f"file:{source}", method="", request_headers=Headers(), status=None, headers=Headers(),
                    body=_read_text(path), source=source, kind="resource")


def iter_input_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        raise CaptureError(f"{root}: no such file or directory")
    files = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if p.suffix.lower() in RAW_SUFFIXES | RESOURCE_SUFFIXES | {".json"}:
            files.append(p)
        if len(files) >= MAX_FILES:
            break
    return files


def load(path: str | Path) -> tuple[list[Exchange], list[str]]:
    """Return (exchanges, errors). JSON files that are not captures are skipped silently in directories."""
    root = Path(path)
    exchanges: list[Exchange] = []
    errors: list[str] = []
    base = root if root.is_dir() else root.parent
    for f in iter_input_files(root):
        source = str(f.relative_to(base)) if base in f.parents or f.parent == base else f.name
        suffix = f.suffix.lower()
        try:
            if suffix in RAW_SUFFIXES:
                exchanges.append(parse_raw_response(_read_text(f), source))
            elif suffix in RESOURCE_SUFFIXES:
                exchanges.append(load_resource(f, source))
            else:
                text = _read_text(f)
                if root.is_dir() and f'"{CAPTURE_FORMAT}"' not in text:
                    continue                     # unrelated JSON (e.g. expected-results file)
                exchanges.extend(parse_json_capture(text, source, f.parent))
        except CaptureError as exc:
            errors.append(str(exc))
    return exchanges, errors
