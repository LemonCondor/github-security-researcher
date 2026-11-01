"""Explorer URL -> (chain_id, address). Closed table: an unrecognised explorer yields chain UNKNOWN, never a guess.

The chain id obtained here is INFERRED (it comes from the explorer host). It only becomes VERIFIED when an RPC
endpoint for that network answers eth_chainId with the same value (see mapper).
Only EVM chains whose runtime bytecode is ordinary EVM are listed: the bytecode classification is meaningless
on non-EVM VMs (e.g. zkSync EraVM), so those explorers are deliberately absent.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# host -> chain id. Hosts with several chains under one domain are handled by _PATH_CHAINS.
_HOST_CHAINS: dict[str, int] = {
    "etherscan.io": 1,
    "eth.blockscout.com": 1,
    "optimistic.etherscan.io": 10,
    "optimism.blockscout.com": 10,
    "bscscan.com": 56,
    "gnosisscan.io": 100,
    "gnosis.blockscout.com": 100,
    "polygonscan.com": 137,
    "uniscan.xyz": 130,
    "sonicscan.org": 146,
    "hyperevmscan.io": 999,
    "basescan.org": 8453,
    "base.blockscout.com": 8453,
    "arbiscan.io": 42161,
    "arbitrum.blockscout.com": 42161,
    "snowtrace.io": 43114,
    "lineascan.build": 59144,
    "scrollscan.com": 534352,
}

# multi-chain explorers: host -> {first path segment -> chain id}
_PATH_CHAINS: dict[str, dict[str, int]] = {
    "oklink.com": {"xlayer": 196},
}

_ADDR = re.compile(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")


def _host(netloc: str) -> str:
    host = netloc.lower().split("@")[-1].split(":")[0]
    return host[4:] if host.startswith("www.") else host


def normalize_address(addr: str | None) -> str | None:
    """Lowercase 0x + 40 hex, or None if it is not exactly one well-formed address."""
    if not addr or not isinstance(addr, str):
        return None
    a = addr.strip()
    return a.lower() if re.fullmatch(r"0x[0-9a-fA-F]{40}", a) else None


def parse_explorer_url(url: str) -> tuple[int | None, str | None, str]:
    """Return (chain_id or None, address or None, explorer host). Never guesses.

    The address is taken only from a path segment that is exactly one address (e.g. /address/0x...);
    a URL carrying zero or several addresses yields None.
    """
    try:
        p = urlparse(url)
    except ValueError:
        return None, None, ""
    host = _host(p.netloc)
    segments = [s for s in p.path.split("/") if s]
    chain = _HOST_CHAINS.get(host)
    if chain is None and host in _PATH_CHAINS and segments:
        chain = _PATH_CHAINS[host].get(segments[0].lower())
    addrs = {m.group(0).lower() for s in segments for m in [_ADDR.fullmatch(s)] if m}
    address = next(iter(addrs)) if len(addrs) == 1 else None
    return chain, address, host


def is_github_url(url: str) -> bool:
    try:
        return _host(urlparse(url).netloc) in ("github.com", "raw.githubusercontent.com")
    except ValueError:
        return False
