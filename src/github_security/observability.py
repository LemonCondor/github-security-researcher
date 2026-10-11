"""Structured JSON-lines logging, always redacted."""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .security.secrets import redact_obj

_log_file: Path | None = None


def configure(log_dir: Path) -> None:
    global _log_file
    log_dir.mkdir(parents=True, exist_ok=True)
    _log_file = log_dir / "events.jsonl"


def event(stage: str, event: str, **fields) -> None:
    rec = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
           "stage": stage, "event": event, **fields}
    line = json.dumps(redact_obj(rec), ensure_ascii=False, default=str)
    if _log_file:
        with _log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    else:
        print(line, file=sys.stderr)


class timed:
    """with timed("clone", "clone_repo", repository=...): ..."""

    def __init__(self, stage: str, name: str, **fields):
        self.stage, self.name, self.fields = stage, name, fields

    def __enter__(self):
        self.t0 = time.monotonic()
        event(self.stage, f"{self.name}.start", **self.fields)
        return self

    def __exit__(self, exc_type, exc, tb):
        ms = int((time.monotonic() - self.t0) * 1000)
        if exc:
            event(self.stage, f"{self.name}.error", duration_ms=ms, error=str(exc), **self.fields)
        else:
            event(self.stage, f"{self.name}.done", duration_ms=ms, **self.fields)
        return False
