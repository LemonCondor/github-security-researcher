"""Read-only JSON-RPC client. Structurally unable to change chain state.

- Method allow-list: eth_chainId, eth_blockNumber, eth_getCode, eth_getStorageAt. Anything else (including
  eth_call, eth_sendRawTransaction, eth_sendTransaction, personal_*) is refused before any network I/O.
- Endpoints come only from the caller or from GSR_RPC_URL_<chain_id>; nothing is hard-coded.
- The full URL is never stored or logged (providers embed API keys in the path); sources keep scheme+host.
- Errors are redacted before being surfaced.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable
from urllib.parse import urlparse

from ..security.secrets import redact

ALLOWED_METHODS = frozenset({"eth_chainId", "eth_blockNumber", "eth_getCode", "eth_getStorageAt"})

Transport = Callable[[str, dict], dict]


class RpcError(RuntimeError):
    pass


def _http_transport(url: str, payload: dict, timeout: int = 20) -> dict:  # pragma: no cover - network
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "user-agent": "github-security-researcher/deploy-mapper"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def rpc_url_for(chain_id: int) -> str | None:
    return os.environ.get(f"GSR_RPC_URL_{chain_id}") or None


def endpoint_label(url: str) -> str:
    """scheme://host only: never the path or query (API keys live there)."""
    p = urlparse(url)
    host = (p.hostname or "unknown").lower()
    return f"{p.scheme or 'https'}://{host}"


class RpcClient:
    def __init__(self, url: str, transport: Transport | None = None):
        self._url = url
        self._transport = transport or _http_transport
        self.label = endpoint_label(url)
        self._id = 0

    def call(self, method: str, params: list) -> object:
        if method not in ALLOWED_METHODS:
            raise RpcError(f"refused non read-only RPC method: {method}")
        self._id += 1
        payload = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        try:
            resp = self._transport(self._url, payload)
        except Exception as e:  # network/transport failure: surfaced, never interpreted
            raise RpcError(redact(f"{self.label} {method}: {type(e).__name__}: {e}")) from None
        if not isinstance(resp, dict):
            raise RpcError(f"{self.label} {method}: malformed response")
        if resp.get("error") is not None:
            raise RpcError(redact(f"{self.label} {method}: {resp['error']}"))
        if "result" not in resp:
            raise RpcError(f"{self.label} {method}: response without result")
        return resp["result"]

    @staticmethod
    def _hex_int(v: object, what: str) -> int:
        if not isinstance(v, str) or not v.startswith("0x"):
            raise RpcError(f"malformed {what}: {v!r}")
        return int(v, 16)

    def chain_id(self) -> int:
        return self._hex_int(self.call("eth_chainId", []), "chain id")

    def block_number(self) -> int:
        return self._hex_int(self.call("eth_blockNumber", []), "block number")

    def get_code(self, address: str, block: int) -> bytes:
        v = self.call("eth_getCode", [address, hex(block)])
        if not isinstance(v, str) or not v.startswith("0x") or len(v) % 2:
            raise RpcError(f"malformed code for {address}")
        return bytes.fromhex(v[2:])

    def get_storage(self, address: str, slot: str, block: int) -> int:
        return self._hex_int(self.call("eth_getStorageAt", [address, slot, hex(block)]), "storage word")
