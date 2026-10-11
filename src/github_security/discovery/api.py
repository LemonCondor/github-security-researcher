"""Read-only GitHub access for discovery: GET only (through github.client.api, i.e. `gh api` without -X/-f),
explicit pagination, quota reserve and error classification. Nothing here can write to GitHub."""
from __future__ import annotations

import re
from typing import Callable

from ..github import client

PER_PAGE = 100
_PATH = re.compile(r"^[A-Za-z0-9._/~-]+(\?[A-Za-z0-9._=&,:+%-]*)?$")


class DiscoveryError(RuntimeError):
    kind = "api_error"


class NotFound(DiscoveryError):
    kind = "not_found"


class RateLimited(DiscoveryError):
    kind = "rate_limited"


def classify(err: Exception) -> DiscoveryError:
    msg = str(err)
    low = msg.lower()
    if "rate limit" in low or "http 429" in low or "secondary rate" in low:
        return RateLimited(msg)
    if "http 404" in low or "not found" in low:
        return NotFound(msg)
    return DiscoveryError(msg)


class ReadOnlyGitHub:
    """`get` returns parsed JSON for a relative API path (default: client.api, read-only by construction)."""

    def __init__(self, get: Callable[[str], object] | None = None, reserve: int = 200):
        self._get = get or client.api
        self.reserve = reserve           # stop before the quota drops below this many calls
        self.calls = 0
        self.remaining: int | None = None

    def get(self, path: str):
        if not _PATH.match(path) or ".." in path:
            raise DiscoveryError(f"refusing api path {path!r}")
        if self.remaining is not None and self.remaining <= self.reserve:
            raise RateLimited(f"quota reserve reached ({self.remaining} calls left, reserve {self.reserve})")
        self.calls += 1
        if self.remaining is not None:
            self.remaining -= 1
        try:
            return self._get(path)
        except DiscoveryError:
            raise
        except Exception as e:  # noqa: BLE001 - GitHubError, JSON errors, timeouts
            raise classify(e) from e

    def check_quota(self) -> int | None:
        """Refresh the remaining core quota (the rate_limit endpoint does not consume quota)."""
        try:
            d = self._get("rate_limit")
        except Exception:  # noqa: BLE001
            return self.remaining
        core = (d.get("resources") or {}).get("core") or {}
        self.remaining = core.get("remaining", self.remaining)
        return self.remaining

    def paginate(self, path: str, max_items: int, key: str | None = None) -> list:
        """Follow ?page=N until a short page or max_items. `key` extracts the list from object responses."""
        out: list = []
        sep = "&" if "?" in path else "?"
        page = 1
        while len(out) < max_items:
            data = self.get(f"{path}{sep}per_page={PER_PAGE}&page={page}")
            items = data.get(key, []) if key and isinstance(data, dict) else data
            if not isinstance(items, list):
                raise DiscoveryError(f"unexpected response for {path}")
            out += items
            if len(items) < PER_PAGE:
                break
            page += 1
        return out[:max_items]
