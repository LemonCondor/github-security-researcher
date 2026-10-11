"""What contracts.solidity/2 covers, and what a static pattern engine cannot prove (returned by run())."""

IMPLEMENTED = {
    "SOL-REENTRANCY": "external .call / interface call before a write to a state variable read before the call, "
                      "no reentrancy-guard modifier (intra-function, single-function reentrancy only)",
    "SOL-ACCESS-CONTROL": "externally callable state-changing function that selfdestructs, has a privileged name "
                          "(mint/setOwner/upgradeTo/withdrawAll/pause...), writes owner/admin/implementation-like "
                          "state or sends address(this).balance, without only*/role modifier or msg.sender check; "
                          "also fallback()/receive(); also a direct write to a state variable whose role is "
                          "derived from its use (compared with msg.sender elsewhere, or a delegatecall target: "
                          "CANDIDATE if the written value is msg.sender or a parameter, else NEEDS_REVIEW); "
                          "pre-0.4.22 constructors (function named like the contract) are not entry points",
    "SOL-TX-ORIGIN": "tx.origin inside a require/assert/if condition (tx.origin == msg.sender EOA check excluded)",
    "SOL-UNPROTECTED-INIT": "public initialize*/init* writing state, no initializer modifier, no one-time guard on "
                            "the written state, no access control",
    "SOL-UNCHECKED-CALL": ".call/.delegatecall/.staticcall/.send whose bool result is discarded or never read; "
                          "inline-assembly call/delegatecall/callcode/staticcall whose success word is never read "
                          "(pop(call(...)) -> NEEDS_REVIEW)",
    "SOL-DELEGATECALL-PARAM": "delegatecall whose target is a parameter of an unrestricted entry point",
    "SOL-UNCHECKED-ARITH": "arithmetic in unchecked{} (loop ++i and bound-checked subtraction excluded) -> NEEDS_REVIEW",
    "SOL-LEGACY-ARITH": "pragma upper bound <0.8.0 and raw +,-,*,++ written to state -> NEEDS_REVIEW",
}

DOCUMENTED_ONLY = {
    "financial-logic": "price/rounding/fee errors, share inflation (ERC4626 first-depositor), wrong accounting: needs "
                       "a spec + Foundry invariant/fuzz tests (forge test --fuzz, invariant_*) or Echidna properties",
    "economic-properties": "flash-loan/oracle manipulation, MEV/sandwich, governance attacks: needs economic "
                           "modelling + forked-mainnet simulation (anvil fork) — out of scope (no chain access)",
    "proxy-storage-layout": "storage collisions between proxy and implementation / across upgrades: needs compiler "
                            "storage layout (solc --storage-layout, slither-check-upgradeability, OZ upgrades plugin)",
    "vulnerable-dependencies": "known-vulnerable OpenZeppelin/solmate versions: needs package manifest/lockfile "
                               "resolution + advisory DB (OSV/GHSA), not source patterns",
    "cross-function-reentrancy": "reentrancy through another function / read-only reentrancy / ERC777 & ERC721 hooks "
                                 "via internal helpers: needs inter-procedural dataflow (Slither) or symbolic "
                                 "execution (Mythril/hevm/halmos)",
    "inherited-or-imported-semantics": "modifiers/functions from imported files outside the scan path are matched "
                                       "by name only; real behaviour needs solc AST + Slither",
    "signature-replay": "missing nonce/chainId/deadline in signed messages: pattern too weak to state without dataflow",
    "dos-gas": "unbounded loops, push-payment DoS: needs gas analysis / fuzzing",
}

ASSUMPTIONS = [
    "syntax-only (tree-sitter), no compilation, no type checking: overloads and storage pointers are not resolved",
    "intra-procedural: writes/calls through internal helpers are not followed",
    "guards are recognised by name (only*, nonReentrant, initializer) unless the modifier body is in the scan path",
    "transfer/send (2300-gas stipend) are not treated as reentrancy vectors",
]
