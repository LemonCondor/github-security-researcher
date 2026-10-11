"""Provider-format secret-like string detection. Values are REDACTED, never validated, never used."""
from __future__ import annotations

import hashlib
import re

# (rule_suffix, label, regex, status, severity, note)
PATTERNS = [
    ("aws-access-key-id", "AWS access key id", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
     "NEEDS_REVIEW", "medium", "a key id alone is not a credential; the secret key may or may not be nearby"),
    ("github-token", "GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,90})\b"),
     "NEEDS_REVIEW", "high", ""),
    ("slack-token", "Slack token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,72})\b"),
     "NEEDS_REVIEW", "medium", ""),
    ("stripe-secret-key", "Stripe secret key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,99})\b"),
     "NEEDS_REVIEW", "high", "publishable pk_live_ keys are public by design and are not reported"),
    ("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
     "OBSERVATION", "info",
     "browser Google API keys are often public by design; only API/referrer restrictions decide the impact"),
    # A PEM marker alone (vendored crypto libraries carry "-----BEGIN RSA PRIVATE KEY-----" as a string constant)
    # is not a key: require base64 key material and the matching END line. Literal "\\n" escapes are allowed.
    ("private-key", "PEM private key block",
     re.compile(r"(-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----)"
                r"(?:\s|\\[rn])+(?:[\w-]+: [^\n\\]{1,200}(?:\s|\\[rn])+)*"   # optional Proc-Type/DEK-Info
                r"[A-Za-z0-9+/=]{16,}(?:(?:\s|\\[rn])+[A-Za-z0-9+/=]+)*(?:\s|\\[rn])*"
                r"-----END \2-----"),
     "NEEDS_REVIEW", "high", ""),
]
ENCRYPTED_KEY = re.compile(r"BEGIN ENCRYPTED PRIVATE KEY|Proc-Type: 4,ENCRYPTED")
_PLACEHOLDER = re.compile(r"EXAMPLE|SAMPLE|PLACEHOLDER|YOUR_|XXXX|xxxx|0000000000|1234567890", re.I)


def redact(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return value                     # the marker line itself carries no key material
    return f"{value[:4]}…[redacted, {len(value)} chars]"


def find_secrets(text: str) -> list[tuple[tuple, str, int, str]]:
    """[(pattern_row, redacted_value, line_number, fingerprint)] — placeholders/documentation keys are skipped.

    The fingerprint (truncated sha256) is only an in-memory dedup key: the engine never outputs it."""
    out, seen = [], set()
    for row in PATTERNS:
        for m in row[2].finditer(text):
            val = m.group(1)
            if _PLACEHOLDER.search(val) or len(set(val[4:])) <= 2:
                continue
            key = (row[0], m.group(0) if row[0] == "private-key" else val)
            if key in seen:
                continue
            seen.add(key)
            if row[0] == "private-key" and ENCRYPTED_KEY.search(m.group(0)):
                row = row[:4] + ("medium", "passphrase-encrypted key: usable only with its passphrase "
                                           "(not searched for, never attempted)")
            # PEM: the fingerprint covers the key material so distinct keys with the same marker are not merged
            fp_src = m.group(0) if row[0] == "private-key" else val
            out.append((row, redact(val), text.count("\n", 0, m.start()) + 1,
                        hashlib.sha256(fp_src.encode()).hexdigest()[:12]))
    return out
