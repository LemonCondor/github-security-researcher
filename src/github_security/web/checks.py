"""Passive checks over captured exchanges. Pure functions: no I/O, no network.

Each check yields ``(dedup_key, kwargs)``; the engine turns kwargs into an ``EngineFinding`` and keeps the first
occurrence per dedup key (later occurrences only increment ``extra["occurrences"]``).
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from ..engines.contract import Evidence
from . import jslibs, secrets
from .capture import Exchange

CAPTURE_LIMIT = "derived from the supplied capture only; the live service was not contacted and may differ"
HARDENING_LIMIT = ("observation, not a demonstrated vulnerability: a missing/weak hardening control is not "
                   "exploitable by itself")
NOT_TESTED = "no active test was performed (no payload, no request replay, no exploitation attempt)"

SESSION_NAME = re.compile(r"(sess|token|auth|jwt|login|remember|(^|[_.-])sid($|[_.-])|^sid)", re.I)
NOT_SESSION = re.compile(r"csrf|xsrf", re.I)
VERSION_RX = re.compile(r"\d+\.\d+")
DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")
HSTS_MIN_AGE = 15552000      # 180 days


def _origin(ex: Exchange) -> str:
    p = urlsplit(ex.url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ex.url


def _ok(ex: Exchange) -> bool:
    return ex.kind == "http" and ex.status is not None and 200 <= ex.status < 300


def _f(rule, category, severity, confidence, status, description, ex: Exchange, loc: dict, evidence, limitations,
       references=(), extra=None, method="pattern"):
    return dict(rule=rule, category=category, severity=severity, confidence=confidence, status=status,
                description=description, evidence=evidence, limitations=limitations, references=list(references),
                location={"url": ex.url, **loc, "source": ex.source}, validation_method=method,
                extra=dict(extra or {}))


def _ev(kind, detail, ex: Exchange, strength="moderate"):
    return Evidence(kind=kind, detail=detail[:300], source=ex.source, strength=strength)


# ---------------------------------------------------------------- security headers
def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks and toks[0].lower() not in out:
            out[toks[0].lower()] = [t.lower() for t in toks[1:]]
    return out


def _script_sources(csp: dict) -> list[str] | None:
    return csp.get("script-src", csp.get("default-src"))


def _csp_unsafe_inline(csp: dict) -> bool:
    src = _script_sources(csp)
    if src is None or "'unsafe-inline'" not in src:
        return False
    # CSP2+: a nonce/hash (or strict-dynamic) makes browsers ignore 'unsafe-inline'
    return not any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) or s == "'strict-dynamic'"
                   for s in src)


def _csp_wildcard(csp: dict) -> str | None:
    src = _script_sources(csp)
    if src is None:
        return "no script-src/default-src directive"
    if "'strict-dynamic'" in src:
        return None              # host/scheme allow-lists are ignored by CSP3 browsers with strict-dynamic
    bad = [s for s in src if s in ("*", "http:", "https:", "data:")]
    return f"script sources allow {' '.join(bad)}" if bad else None


def check_headers(ex: Exchange):
    if not _ok(ex):
        return
    host, h = ex.host, ex.headers
    common = [CAPTURE_LIMIT, HARDENING_LIMIT]
    if ex.scheme == "https":
        hsts = h.get("strict-transport-security")
        if hsts is None:
            yield ("hsts-missing", host), _f(
                "web.hdr.hsts-missing", "security-headers", "low", 0.9, "OBSERVATION",
                "HTTPS response without Strict-Transport-Security", ex, {"header": "Strict-Transport-Security"},
                [_ev("http-header", "Strict-Transport-Security absent on an https 2xx response", ex)],
                common + ["HSTS preload-list membership was not checked (offline)"],
                ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security"])
        else:
            m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else -1
            if age < HSTS_MIN_AGE:
                yield ("hsts-short", host), _f(
                    "web.hdr.hsts-short-max-age", "security-headers", "info", 0.9, "OBSERVATION",
                    "HSTS max-age missing or shorter than 180 days", ex, {"header": "Strict-Transport-Security"},
                    [_ev("http-header", f"Strict-Transport-Security: {hsts}", ex)], common)
    if (h.get("x-content-type-options") or "").strip().lower() != "nosniff":
        yield ("xcto", host), _f(
            "web.hdr.xcto-missing", "security-headers", "info", 0.9, "OBSERVATION",
            "X-Content-Type-Options: nosniff absent", ex, {"header": "X-Content-Type-Options"},
            [_ev("http-header", f"X-Content-Type-Options: {h.get('x-content-type-options')!r}", ex)], common)
    if not ex.is_html():
        return
    csps = [parse_csp(v) for v in h.get_all("content-security-policy")]
    if not csps:
        ro = " (only Content-Security-Policy-Report-Only, which does not enforce)" \
            if h.has("content-security-policy-report-only") else ""
        yield ("csp-missing", host), _f(
            "web.hdr.csp-missing", "security-headers", "low", 0.85, "OBSERVATION",
            "HTML response without an enforced Content-Security-Policy" + ro, ex,
            {"header": "Content-Security-Policy"},
            [_ev("http-header", "Content-Security-Policy absent" + ro, ex)],
            common + ["a <meta http-equiv> CSP in the body is not evaluated by this rule"])
    else:
        # several enforced policies are intersected: a weakness counts only if every policy has it
        if all(_csp_unsafe_inline(c) for c in csps):
            yield ("csp-inline", host), _f(
                "web.hdr.csp-unsafe-inline", "security-headers", "low", 0.8, "OBSERVATION",
                "CSP allows 'unsafe-inline' scripts without nonce/hash", ex, {"header": "Content-Security-Policy"},
                [_ev("http-header", "Content-Security-Policy: " + "; ".join(h.get_all("content-security-policy")), ex)],
                common + ["weakens XSS mitigation only; no XSS was found or tested"])
        reasons = [_csp_wildcard(c) for c in csps]
        if all(reasons):
            yield ("csp-wild", host), _f(
                "web.hdr.csp-wildcard-script", "security-headers", "low", 0.8, "OBSERVATION",
                "CSP does not restrict script origins (" + reasons[0] + ")", ex,
                {"header": "Content-Security-Policy"},
                [_ev("http-header", "Content-Security-Policy: " + "; ".join(h.get_all("content-security-policy")), ex)],
                common + ["weakens XSS mitigation only; no XSS was found or tested"])
    if not any("frame-ancestors" in c for c in csps):
        xfo = (h.get("x-frame-options") or "").strip().upper()
        if xfo not in ("DENY", "SAMEORIGIN"):
            yield ("frame", host), _f(
                "web.hdr.frame-protection-missing", "security-headers", "low", 0.8, "OBSERVATION",
                "no CSP frame-ancestors and no X-Frame-Options DENY/SAMEORIGIN", ex,
                {"header": "X-Frame-Options"},
                [_ev("http-header", f"X-Frame-Options: {h.get('x-frame-options')!r}; no frame-ancestors", ex)],
                common + ["clickjacking impact depends on state-changing UI on the page; not assessed"])
    rp = (h.get("referrer-policy") or "").lower()
    if not rp and re.search(r"<meta[^>]+name\s*=\s*[\"']referrer[\"']", ex.body, re.I):
        rp = "meta"
    if not rp:
        yield ("ref-missing", host), _f(
            "web.hdr.referrer-policy-missing", "security-headers", "info", 0.85, "OBSERVATION",
            "Referrer-Policy absent (modern browsers default to strict-origin-when-cross-origin)", ex,
            {"header": "Referrer-Policy"}, [_ev("http-header", "Referrer-Policy absent", ex)], common)
    elif rp != "meta" and rp.split(",")[-1].strip() in ("unsafe-url", "no-referrer-when-downgrade"):
        yield ("ref-unsafe", host), _f(
            "web.hdr.referrer-policy-unsafe", "security-headers", "info", 0.85, "OBSERVATION",
            "Referrer-Policy leaks full URLs cross-origin", ex, {"header": "Referrer-Policy"},
            [_ev("http-header", f"Referrer-Policy: {rp}", ex)], common)


# ---------------------------------------------------------------- redirects
def check_redirects(ex: Exchange):
    if ex.kind != "http" or ex.status is None:
        return
    lims = [CAPTURE_LIMIT, NOT_TESTED]
    if ex.scheme == "http" and 200 <= ex.status < 300:
        yield ("plain-http", ex.host), _f(
            "web.redirect.no-https-upgrade", "transport", "low", 0.8, "OBSERVATION",
            "content served over plain HTTP without redirect to HTTPS", ex, {"header": "Location"},
            [_ev("http-exchange", f"{ex.method} {ex.url} -> {ex.status} (no redirect)", ex)],
            lims + [HARDENING_LIMIT])
    if not (300 <= ex.status < 400):
        return
    loc = ex.headers.get("location")
    if not loc:
        return
    target = urljoin(ex.url, loc) if ex.url else loc
    tparts = urlsplit(target)
    if ex.scheme == "https" and tparts.scheme == "http":
        yield ("downgrade", ex.url), _f(
            "web.redirect.https-downgrade", "transport", "low", 0.85, "OBSERVATION",
            "HTTPS response redirects to plain HTTP", ex, {"header": "Location"},
            [_ev("http-header", f"{ex.url} -> Location: {loc}", ex)], lims + [HARDENING_LIMIT])
    if not ex.url:
        return
    thost = (tparts.hostname or "").lower()
    if not thost or thost == ex.host:
        return
    for name, value in parse_qsl(urlsplit(ex.url).query, keep_blank_values=False):
        v = unquote(value).strip()
        if len(v) < 4:
            continue
        vhost = (urlsplit(urljoin(ex.url, v)).hostname or "").lower()
        if vhost == thost and (loc.startswith(v) or target.startswith(urljoin(ex.url, v))):
            yield ("open-redirect", ex.url, name), _f(
                "web.redirect.open-redirect-candidate", "redirect", "medium", 0.4, "NEEDS_REVIEW",
                f"cross-host Location appears built from query parameter {name!r}", ex,
                {"header": "Location", "parameter": name},
                [_ev("http-exchange", f"param {name}={v[:120]} -> {ex.status} Location: {loc[:160]}", ex)],
                lims + ["one captured sample: an allow-list may still exist (e.g. this host is permitted); "
                        "arbitrary-destination redirection was NOT demonstrated"],
                ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"])
            return


# ---------------------------------------------------------------- cookies
def parse_set_cookie(value: str) -> tuple[str, str, dict[str, str]]:
    parts = [p.strip() for p in value.split(";")]
    name, _, val = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        if p:
            k, _, v = p.partition("=")
            attrs[k.strip().lower()] = v.strip()
    return name.strip(), val.strip(), attrs


def _is_session(name: str) -> bool:
    return bool(SESSION_NAME.search(name)) and not NOT_SESSION.search(name)


def check_cookies(ex: Exchange):
    if ex.kind != "http":
        return
    for raw in ex.headers.get_all("set-cookie"):
        name, val, attrs = parse_set_cookie(raw)
        if not name:
            continue
        ma = attrs.get("max-age", "")
        if not val or (ma.lstrip("-").isdigit() and int(ma) <= 0):
            continue                              # deletion cookie
        secure, httponly = "secure" in attrs, "httponly" in attrs
        samesite = attrs.get("samesite", "").lower() if "samesite" in attrs else None
        session = _is_session(name)
        flags = " ".join(k for k in ("secure", "httponly") if k in attrs) + \
            (f" samesite={samesite}" if samesite is not None else "")
        ev = [_ev("cookie", f"Set-Cookie {name}=<redacted>; attrs: {flags.strip() or 'none'}", ex)]
        loc = {"cookie": name}
        lims = [CAPTURE_LIMIT, HARDENING_LIMIT]
        key = (ex.host, name)
        if ex.scheme == "https" and not secure:
            yield ("ck-secure",) + key, _f(
                "web.cookie.secure-missing", "cookies", "low" if session else "info", 0.85, "OBSERVATION",
                f"cookie {name!r} set over HTTPS without Secure", ex, loc, ev, lims)
        if session and not httponly:
            yield ("ck-httponly",) + key, _f(
                "web.cookie.httponly-missing", "cookies", "low", 0.6, "OBSERVATION",
                f"session-like cookie {name!r} without HttpOnly", ex, loc, ev,
                lims + ["'session-like' is a name heuristic; the cookie may be meant for JavaScript"])
        if samesite == "none" and not secure:
            yield ("ck-ss-none",) + key, _f(
                "web.cookie.samesite-none-insecure", "cookies", "info", 0.9, "OBSERVATION",
                f"cookie {name!r} has SameSite=None without Secure (rejected by modern browsers)", ex, loc, ev, lims)
        elif session and samesite is None:
            yield ("ck-ss-missing",) + key, _f(
                "web.cookie.samesite-missing", "cookies", "info", 0.6, "OBSERVATION",
                f"session-like cookie {name!r} without SameSite (browser defaults differ)", ex, loc, ev,
                lims + ["no CSRF was tested"])
        problems = []
        if name.startswith(("__Secure-", "__Host-")) and not secure:
            problems.append("prefix requires Secure")
        if name.startswith("__Host-"):
            if "domain" in attrs:
                problems.append("__Host- forbids Domain")
            if attrs.get("path") != "/":
                problems.append("__Host- requires Path=/")
        if problems:
            yield ("ck-prefix",) + key, _f(
                "web.cookie.prefix-violation", "cookies", "low", 0.95, "OBSERVATION",
                f"cookie {name!r} violates its name-prefix rules ({'; '.join(problems)}); browsers reject it",
                ex, loc, ev, lims, ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie#cookie_prefixes"])


# ---------------------------------------------------------------- disclosure
STACK_PATTERNS = [
    ("python-traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("java-stack", re.compile(r"\n\s*at [a-zA-Z_$][\w$]*(?:\.[\w$<>]+)+\([\w$]+\.java:\d+\)")),
    ("php-error", re.compile(r"(?:Fatal error|Parse error|Uncaught \w+)(?:</b>)?:.{0,300}? in (?:<b>)?/[^<\s]+"
                             r"(?:</b>)? on line (?:<b>)?\d+", re.S)),
    ("dotnet-ysod", re.compile(r"Server Error in '[^']*' Application")),
    ("node-stack", re.compile(r"\n\s+at .{1,200} \((?:/|[A-Z]:\\)[^)]+\.(?:js|ts|mjs):\d+:\d+\)")),
    # Go runtime panic: "goroutine 42 [running]:" followed by a frame "\t/path/file.go:118"
    ("go-panic", re.compile(r"goroutine \d+ \[[\w ,]+\]:\n.{1,300}?\n\s+\S+\.go:\d+", re.S)),
    # Rust: "thread 'main' panicked at src/x.rs:57:31" (and pre-1.73 form "panicked at '<msg>', src/x.rs:57:31")
    ("rust-panic", re.compile(r"thread '[^'\n]{1,100}' panicked at .{0,300}?[\w./-]+\.rs:\d+:\d+")),
    # Ruby backtrace frame: "/srv/app/x.rb:12:in `show'"
    ("ruby-backtrace", re.compile(r"(?:^|\s)/[\w./-]+\.rb:\d+:in [`'][^'\n]{1,120}'", re.M)),
]
DEBUG_PATTERNS = [
    ("django-debug", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>")),
    ("werkzeug-debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception in your WSGI application")),
    ("laravel-ignition", re.compile(r"Whoops! There was an error\.|window\.ignite|Illuminate\\\\Foundation")),
    ("rails-debug", re.compile(r"Action Controller: Exception caught")),
    ("symfony-debug", re.compile(r"Symfony\\\\Component\\\\ErrorHandler|sf-toolbar")),
]
DIRLIST = re.compile(r"<title>\s*(?:Index of /|Directory listing for /)", re.I)
SOURCEMAP = re.compile(r"^[ \t]*//[#@][ \t]*sourceMappingURL=(?!data:)(\S+)", re.M)
ENV_LINE = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]{1,63})=")
ENV_SENSITIVE = re.compile(r"PASS|SECRET|KEY|TOKEN|DATABASE_URL|DB_|CREDENTIAL|PRIVATE", re.I)


def check_disclosure(ex: Exchange):
    lims = [CAPTURE_LIMIT, NOT_TESTED]
    if ex.kind == "http":
        for hn in DISCLOSURE_HEADERS:
            for v in ex.headers.get_all(hn):
                if VERSION_RX.search(v):
                    yield ("ver", ex.host, hn), _f(
                        "web.disclosure.version-header", "information-disclosure", "info", 0.9, "OBSERVATION",
                        f"{hn} header discloses a software version", ex, {"header": hn},
                        [_ev("http-header", f"{hn}: {v}", ex)],
                        lims + ["version strings can be spoofed or back-patched; no vulnerability is implied"])
        body = ex.body
        if DIRLIST.search(body[:5000]):
            yield ("dirlist", ex.url), _f(
                "web.disclosure.directory-listing", "information-disclosure", "low", 0.8, "NEEDS_REVIEW",
                "auto-generated directory listing page", ex, {"resource": ex.url},
                [_ev("body", DIRLIST.search(body[:5000]).group(0), ex)],
                lims + ["listed files were not fetched; sensitivity of the content is unknown"])
        if not ex.is_js():
            for label, rx in DEBUG_PATTERNS:
                m = rx.search(body)
                if m:
                    yield ("debug", ex.url), _f(
                        "web.disclosure.debug-page", "information-disclosure", "medium", 0.75, "CANDIDATE",
                        f"framework debug page in response ({label})", ex, {"resource": ex.url},
                        [_ev("body", f"{label}: {m.group(0)[:120]}", ex, "strong")],
                        lims + ["debug mode is observed in this capture only; code execution through a debugger "
                                "console was NOT attempted"])
                    break
            else:
                for label, rx in (STACK_PATTERNS if ex.status and ex.status >= 400 else ()):
                    m = rx.search(body)
                    if m:
                        yield ("stack", ex.url), _f(
                            "web.disclosure.stack-trace", "information-disclosure", "low", 0.7, "NEEDS_REVIEW",
                            f"stack trace / error details in response ({label})", ex, {"resource": ex.url},
                            [_ev("body", f"{label}: {m.group(0).strip()[:120]}", ex)],
                            lims + ["reveals internals (paths, frameworks); not a vulnerability by itself",
                                    "only error responses (status >= 400) are inspected for stack traces"])
                        break
        if not ex.is_html():
            yield from _check_env_git(ex, lims)
        for hn in ("sourcemap", "x-sourcemap"):
            v = ex.headers.get(hn)
            if v:
                yield ("smap", ex.url), _f(
                    "web.disclosure.sourcemap-reference", "information-disclosure", "info", 0.9, "OBSERVATION",
                    "response references a source map", ex, {"header": hn},
                    [_ev("http-header", f"{hn}: {v}", ex)],
                    lims + ["the map file was not fetched; whether it is public and contains sources is unknown"])
    if ex.is_js() or ex.url.endswith((".js", ".mjs")):
        m = SOURCEMAP.search(ex.body)
        if m:
            yield ("smap", ex.url), _f(
                "web.disclosure.sourcemap-reference", "information-disclosure", "info", 0.9, "OBSERVATION",
                "JavaScript references a source map", ex, {"resource": ex.url},
                [_ev("body", f"sourceMappingURL={m.group(1)[:160]}", ex)],
                lims + ["the map file was not fetched; whether it is public and contains sources is unknown"])


def _check_env_git(ex: Exchange, lims):
    body = ex.body
    lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if lines:
        keys = [m.group(1) for m in (ENV_LINE.match(ln) for ln in lines) if m]
        if len(keys) >= 3 and len(keys) / len(lines) >= 0.6 and any(ENV_SENSITIVE.search(k) for k in keys):
            yield ("env", ex.url), _f(
                "web.disclosure.env-file", "information-disclosure", "high", 0.75, "CANDIDATE",
                "response body looks like a dotenv file with sensitive keys", ex, {"resource": ex.url},
                [_ev("body", "dotenv-like keys (values redacted): " + ", ".join(keys[:12]), ex, "strong")],
                lims + ["values were neither shown nor used/validated; whether they are real or placeholders "
                        "is unknown"])
    if (re.search(r"^\[core\]\s*$", body, re.M) and "repositoryformatversion" in body) or \
            re.fullmatch(r"\s*ref: refs/heads/[\w./-]+\s*", body):
        yield ("git", ex.url), _f(
            "web.disclosure.git-metadata", "information-disclosure", "medium", 0.8, "CANDIDATE",
            "response body looks like Git repository metadata (.git/config or .git/HEAD)", ex,
            {"resource": ex.url}, [_ev("body", body.strip().splitlines()[0][:80], ex, "strong")],
            lims + ["no other .git object was fetched; repository reconstruction was NOT attempted"])


# ---------------------------------------------------------------- JS libraries
def check_jslibs(ex: Exchange):
    hits: list[tuple[str, str, str, str, float]] = []     # lib, version, marker, resource, confidence
    if ex.is_js() or ex.kind == "resource":
        for lib, ver, marker in jslibs.detect_in_body(ex.body):
            hits.append((lib, ver, marker, ex.url, 0.65))
        if ex.kind == "http":
            for lib, ver, marker in jslibs.detect_in_url(ex.url):
                hits.append((lib, ver, "file name/path", ex.url, 0.45))
    if ex.is_html() or ex.url.endswith((".html", ".htm")):
        for src in jslibs.script_srcs(ex.body):
            full = urljoin(ex.url, src) if ex.kind == "http" else src
            for lib, ver, marker in jslibs.detect_in_url(src):
                hits.append((lib, ver, "script src", full, 0.45))
    for lib, ver, marker, resource, conf in hits:
        vulns = jslibs.known_vulns(lib, ver)
        if not vulns:
            continue
        sev_order = ("info", "low", "medium", "high", "critical")
        sev = max((v[4] for v in vulns), key=sev_order.index)
        ids = [v[3] for v in vulns]
        refs = [r for v in vulns for r in v[6]]
        yield ("jslib", lib, ver), _f(
            "web.js.known-vulnerable-library", "vulnerable-component", sev, conf, "CANDIDATE",
            f"{lib} {ver} falls in published affected ranges: {', '.join(ids)}", ex,
            {"resource": resource, "library": f"{lib}@{ver}"},
            [_ev("js-library", f"{lib} {ver} detected via {marker}", ex),
             *[_ev("advisory", f"{v[3]} affects {lib} >={v[1]} <{v[2]}: {v[5]}", ex, "weak") for v in vulns]],
            [CAPTURE_LIMIT, "reachability/exploitability not shown: the vulnerable API may never be called",
             "version inferred from banner/file name; vendors sometimes back-port fixes",
             f"local advisory table snapshot {jslibs.TABLE_SNAPSHOT}; not exhaustive (no OSV/network lookup)"],
            refs, {"advisories": ids})


# ---------------------------------------------------------------- secret-like strings
def check_secrets(ex: Exchange):
    if not (ex.is_html() or ex.is_js() or ex.kind == "resource" or ex.content_type.startswith(("text/", "application/json"))):
        return
    for row, red, line, fp in secrets.find_secrets(ex.body):
        suffix, label, _rx, status, sev, note = row
        lims = [CAPTURE_LIMIT, "secret-like by format only: the value was NOT validated or used against any service",
                "it may be a test/revoked/public value"]
        if note:
            lims.append(note)
        yield ("secret", ex.url, suffix, fp), _f(
            f"web.secret.{suffix}", "secret-exposure", sev, 0.5, status,
            f"{label}-like string in client-side content", ex, {"resource": ex.url, "line": line},
            [_ev("secret-pattern", f"{label}: {red} (line {line})", ex)], lims)


# ---------------------------------------------------------------- CORS
def check_cors(ex: Exchange):
    if ex.kind != "http":
        return
    acao = (ex.headers.get("access-control-allow-origin") or "").strip()
    if not acao:
        return
    creds = (ex.headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    origin = (ex.request_headers.get("origin") or "").strip()
    ev = [_ev("http-header", f"request Origin: {origin or '-'}; Access-Control-Allow-Origin: {acao}; "
                             f"Access-Control-Allow-Credentials: {'true' if creds else 'absent/false'}", ex)]
    lims = [CAPTURE_LIMIT, NOT_TESTED]
    if acao == "*" and creds:
        yield ("cors-wild", ex.host), _f(
            "web.cors.wildcard-with-credentials", "cors", "low", 0.85, "OBSERVATION",
            "Access-Control-Allow-Origin: * combined with Allow-Credentials: true", ex,
            {"header": "Access-Control-Allow-Origin"}, ev,
            lims + ["browsers refuse credentialed requests with a wildcard origin: this indicates a misconfigured "
                    "CORS layer, not a demonstrated data leak"])
    elif acao.lower() == "null" and creds:
        yield ("cors-null", ex.host), _f(
            "web.cors.null-origin-credentials", "cors", "medium", 0.5, "NEEDS_REVIEW",
            "credentialed CORS allowed for Origin: null", ex, {"header": "Access-Control-Allow-Origin"}, ev,
            lims + ["sandboxed documents can send Origin: null; data exposure was NOT demonstrated"])
    elif origin and acao == origin and (urlsplit(origin).hostname or "").lower() != ex.host:
        vary = [t.strip().lower() for v in ex.headers.get_all("vary") for t in v.split(",")]
        vary_origin = "origin" in vary or "*" in vary
        ev.append(_ev("http-header", "Vary: " + (", ".join(ex.headers.get_all("vary")) or "absent")
                      + ("" if vary_origin else " (Origin not listed)"), ex, "weak"))
        if not vary_origin:
            lims = lims + ["Vary: Origin absent: a shared cache could replay this origin-specific "
                           "Access-Control-Allow-Origin to other origins; cache behaviour was NOT tested"]
        yield ("cors-reflect", ex.host), _f(
            "web.cors.reflected-origin", "cors", "medium" if creds else "low", 0.45 if creds else 0.35,
            "NEEDS_REVIEW" if creds else "OBSERVATION",
            "cross-origin request Origin echoed in Access-Control-Allow-Origin"
            + (" with credentials" if creds else ""), ex, {"header": "Access-Control-Allow-Origin"}, ev,
            lims + ["a single echoed origin may be a legitimate allow-list entry; arbitrary-origin reflection "
                    "was NOT demonstrated (would need an authorized active test)"],
            ["https://portswigger.net/web-security/cors"], {"vary_origin": vary_origin})


# ---------------------------------------------------------------- explicit non-applicability
HTML_ONLY_CHECKS = ("content-security-policy", "frame-protection (frame-ancestors / X-Frame-Options)",
                    "referrer-policy")


def not_applicable(ex: Exchange) -> str | None:
    """Reason why the HTML-only header checks were skipped for this exchange (None = they ran / not relevant).

    Policy: CSP, frame-ancestors/X-Frame-Options and Referrer-Policy protect documents a browser renders. On a
    non-HTML 2xx response (e.g. application/json) their absence is low value and is NOT reported as a finding;
    the skip is listed in the run output so it is never a silent gap."""
    if _ok(ex) and not ex.is_html():
        return f"content-type: {ex.content_type or 'absent'} (not HTML)"
    return None


ALL_CHECKS = (check_headers, check_redirects, check_cookies, check_disclosure, check_jslibs, check_secrets,
              check_cors)
