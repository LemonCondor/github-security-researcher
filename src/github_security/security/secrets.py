"""Secret redaction. Applied to every log line and every subprocess output we persist."""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                 # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),               # fine-grained PAT
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),                 # Anthropic
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                        # OpenAI-style
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),                       # Groq
    re.compile(r"AKIA[0-9A-Z]{16}"),                           # AWS access key id
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),               # Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(authorization:\s*(?:bearer|token|basic)\s+)\S+"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)['\"]?[^\s'\"]{6,}"),
    re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"),             # creds in URLs
]

REDACTED = "[REDACTED]"


def redact(text: str) -> str:
    if not text:
        return text
    for pat in _PATTERNS:
        if pat.groups:
            text = pat.sub(lambda m: m.group(1) + REDACTED, text)
        else:
            text = pat.sub(REDACTED, text)
    return text


def redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj
