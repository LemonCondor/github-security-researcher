"""JavaScript library/version detection + a SMALL, static, local known-vulnerable table.

No OSV/NVD/network lookups. The table is a hand-maintained snapshot (see TABLE_SNAPSHOT) and is NOT exhaustive:
absence of a match never means "not vulnerable". A match only says "this version string falls in a published
affected range"; reachability/exploitability is never shown.
"""
from __future__ import annotations

import re

TABLE_SNAPSHOT = "2026-10-09 (hand-curated, partial)"

# (library, low_inclusive, high_exclusive, id, severity, summary, references)
KNOWN_VULNERABLE = [
    ("jquery", "0", "1.9.0", "CVE-2012-6708", "medium",
     "jQuery() selector string may be interpreted as HTML (XSS) when it does not start with '<'",
     ["https://nvd.nist.gov/vuln/detail/CVE-2012-6708"]),
    ("jquery", "0", "3.0.0", "CVE-2015-9251", "medium",
     "cross-domain ajax responses with text/javascript are executed without dataType",
     ["https://nvd.nist.gov/vuln/detail/CVE-2015-9251"]),
    ("jquery", "0", "3.4.0", "CVE-2019-11358", "medium",
     "jQuery.extend(true, ...) prototype pollution via __proto__",
     ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"]),
    ("jquery", "1.2", "3.5.0", "CVE-2020-11022", "medium",
     "untrusted HTML passed to DOM manipulation methods may execute code (htmlPrefilter)",
     ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"]),
    ("jquery", "1.0.3", "3.5.0", "CVE-2020-11023", "medium",
     "HTML containing <option> elements passed to DOM manipulation methods may execute code",
     ["https://nvd.nist.gov/vuln/detail/CVE-2020-11023"]),
    ("angularjs", "0", "1.7.9", "CVE-2019-10768", "medium",
     "merge() prototype pollution", ["https://nvd.nist.gov/vuln/detail/CVE-2019-10768"]),
    ("angularjs", "0", "1.8.0", "CVE-2020-7676", "medium",
     "XSS via <option> elements in <select> (jqLite/sanitizer)",
     ["https://nvd.nist.gov/vuln/detail/CVE-2020-7676"]),
    ("angularjs", "0", "999", "EOL-angularjs", "low",
     "AngularJS 1.x is end-of-life (Dec 2021): later published issues (e.g. CVE-2022-25844 ReDoS) are unpatched",
     ["https://docs.angularjs.org/misc/version-support-status"]),
    ("lodash", "0", "4.17.12", "CVE-2019-10744", "high",
     "defaultsDeep prototype pollution", ["https://nvd.nist.gov/vuln/detail/CVE-2019-10744"]),
    ("lodash", "0", "4.17.21", "CVE-2021-23337", "high",
     "command injection via template() (exploitable only when attacker controls template options)",
     ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]),
    ("bootstrap", "0", "3.4.1", "CVE-2019-8331", "medium",
     "XSS in tooltip/popover data-template / data-content / data-title",
     ["https://nvd.nist.gov/vuln/detail/CVE-2019-8331"]),
    ("bootstrap", "4.0.0", "4.3.1", "CVE-2019-8331", "medium",
     "XSS in tooltip/popover data-template / data-content / data-title",
     ["https://nvd.nist.gov/vuln/detail/CVE-2019-8331"]),
    ("moment", "0", "2.19.3", "CVE-2017-18214", "low",
     "ReDoS in date parsing", ["https://nvd.nist.gov/vuln/detail/CVE-2017-18214"]),
    ("moment", "1.0.1", "2.29.2", "CVE-2022-24785", "medium",
     "path traversal in moment.locale() when a user-controlled locale string is used (server-side/Node usage)",
     ["https://nvd.nist.gov/vuln/detail/CVE-2022-24785"]),
    ("moment", "2.18.0", "2.29.4", "CVE-2022-31129", "medium",
     "ReDoS in RFC 2822 date parsing of long user-supplied strings",
     ["https://nvd.nist.gov/vuln/detail/CVE-2022-31129"]),
]

_V = r"(\d+\.\d+(?:\.\d+)?)"
# Banner / in-code markers (searched in JS bodies and inline scripts). Each pattern is anchored on the library's
# REAL distribution banner format (license comment layout + what follows the version), so that a version merely
# mentioned in an unrelated comment ("requires jQuery v1.7", "Bootstrap v3.3.7 compatible theme") does not match.
_C = r"/\*[!*]?[\s*]*"           # comment opener followed by blank / " * " continuation lines
BODY_PATTERNS = [
    # /*! jQuery v1.12.4 | (c) ... */   (also slim builds: "/*! jQuery v3.3.1 -ajax,-effects | (c) ...")
    ("jquery", re.compile(_C + r"jQuery\s+v" + _V + r"(?=[^\n|*]{0,600}\|)")),
    # /*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/
    ("jquery", re.compile(_C + r"jQuery JavaScript Library v" + _V + r"[ \t]*\r?\n")),
    # @license AngularJS v1.8.3  |  /*\n AngularJS v1.6.9\n (c) 2010-2018 Google
    ("angularjs", re.compile(r"@license\s+AngularJS\s+v" + _V)),
    ("angularjs", re.compile(_C + r"AngularJS\s+v" + _V + r"[ \t]*\r?\n[\s*]*\(c\)")),
    # lodash 3.x: "@license lodash 3.10.1 (Custom Build)" / " * @license\n * lodash 3.10.1 (Custom Build)"
    ("lodash", re.compile(r"@license[\s*]+lodash\s+" + _V + r"\s+\(Custom Build\)", re.I)),
    # lodash.js 4.x: license banner, then "var VERSION = '4.17.4';" within the first few KB
    ("lodash", re.compile(r"@license[\s*]+Lodash\s+<https://lodash\.com/>.{0,3000}?\bVERSION\s*=\s*[\"']"
                          + _V + r"[\"']", re.S)),
    # lodash.min.js 4.x: "@license Lodash lodash.com/license" banner; VERSION is the minified var right before
    # LARGE_ARRAY_SIZE (=200), e.g. 'var u,i="4.17.15",o=200,'
    ("lodash", re.compile(r"@license[\s*]+Lodash\s+lodash\.com/license.{0,20000}?[,\s]\w{1,3}=[\"']"
                          r"(\d+\.\d+\.\d+)[\"'],\w{1,3}=200\b", re.S)),
    # /*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)   |   Bootstrap v4.3.1 (https://getbootstrap.com/)
    ("bootstrap", re.compile(r"\*\s*Bootstrap\s+v" + _V + r"(?=[ \t]*(?:\(https?://getbootstrap\.com|\r?\n))")),
    # //! moment.js\n//! version : 2.29.1   (moment-timezone.js and locale files do not match)
    ("moment", re.compile(r"//!\s*moment\.js[ \t]*\r?\n//!\s*version\s*:\s*" + _V)),
]
# File name / CDN path markers (script src or resource URL).
URL_PATTERNS = [
    ("jquery", re.compile(r"jquery[-.@/]v?" + _V + r"(?:[./-]|$)", re.I)),
    ("angularjs", re.compile(r"angular(?:js|\.js)?[-@/]v?" + _V + r"(?:[./-]|$)", re.I)),
    ("lodash", re.compile(r"lodash(?:\.js)?[-.@/]v?" + _V + r"(?:[./-]|$)", re.I)),
    ("bootstrap", re.compile(r"bootstrap[-@/]v?" + _V + r"(?:[./-]|$)", re.I)),
    ("moment", re.compile(r"moment(?:\.js)?[-.@/]v?" + _V + r"(?:[./-]|$)", re.I)),
]
SCRIPT_SRC = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)


def vtuple(v: str) -> tuple[int, ...]:
    parts = [int(p) for p in re.findall(r"\d+", v)[:3]]
    return tuple(parts + [0] * (3 - len(parts)))


def detect_in_body(body: str) -> list[tuple[str, str, str]]:
    """[(library, version, marker)]"""
    out = []
    for lib, rx in BODY_PATTERNS:
        m = rx.search(body)
        if m:
            out.append((lib, m.group(1), m.group(0)[:80].replace("\n", " ")))
    return out


def detect_in_url(url: str) -> list[tuple[str, str, str]]:
    out = []
    for lib, rx in URL_PATTERNS:
        m = rx.search(url)
        if m:
            out.append((lib, m.group(1), url[:200]))
    return out


def script_srcs(html: str) -> list[str]:
    return SCRIPT_SRC.findall(html)


def is_partial(version: str) -> bool:
    """A 2-part version ("4.17", e.g. a CDN path jsdelivr ``lodash@4.17``) is a RANGE, not an exact version."""
    return len(re.findall(r"\d+", version)) < 3


def known_vulns(lib: str, version: str) -> list[tuple]:
    """Advisories whose affected range contains the version. For a partial version (major.minor = a range of
    patch releases) an advisory counts only if EVERY patch release of that minor is affected (no over-claim)."""
    v = vtuple(version)
    if is_partial(version):
        nxt = (v[0], v[1] + 1, 0)
        return [row for row in KNOWN_VULNERABLE
                if row[0] == lib and vtuple(row[1]) <= v and nxt <= vtuple(row[2])]
    return [row for row in KNOWN_VULNERABLE
            if row[0] == lib and vtuple(row[1]) <= v < vtuple(row[2])]
