"""Static facts about EVM runtime bytecode. Pure functions, no execution of the code.

`delegating_opcodes` walks the instruction stream skipping PUSH immediates, after removing the trailing solc
CBOR metadata, so constants and metadata bytes are never mistaken for DELEGATECALL (0xf4) / CALLCODE (0xf2).
Error direction is deliberate: a data region misread as code can only ADD a delegating opcode, which makes the
contract UNKNOWN rather than DIRECT; it can never hide a real one that sits in executable code.
"""
from __future__ import annotations

import hashlib

DELEGATECALL = 0xF4
CALLCODE = 0xF2

# EIP-1167 canonical minimal proxy runtime: prefix + 20-byte target + suffix (45 bytes)
_EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
_EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")


def code_sha256(code: bytes) -> str:
    return hashlib.sha256(code).hexdigest()


def strip_metadata(code: bytes) -> bytes:
    """Remove solc's trailing CBOR metadata (map + 2-byte big-endian length) when it is clearly present."""
    if len(code) < 4:
        return code
    n = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - n
    if 0 < n and start >= 0 and 0xA1 <= code[start] <= 0xA5:   # CBOR map with 1..5 entries
        return code[:start]
    return code


def delegating_opcodes(code: bytes) -> set[str]:
    found: set[str] = set()
    body = strip_metadata(code)
    i = 0
    while i < len(body):
        op = body[i]
        if 0x60 <= op <= 0x7F:            # PUSH1..PUSH32: skip immediate data
            i += op - 0x5F + 1
            continue
        if op == DELEGATECALL:
            found.add("DELEGATECALL")
        elif op == CALLCODE:
            found.add("CALLCODE")
        i += 1
    return found


def eip1167_target(code: bytes) -> str | None:
    """Target address of a canonical EIP-1167 minimal proxy, else None (variants are not recognised)."""
    if len(code) == 45 and code.startswith(_EIP1167_PREFIX) and code.endswith(_EIP1167_SUFFIX):
        return "0x" + code[10:30].hex()
    return None
