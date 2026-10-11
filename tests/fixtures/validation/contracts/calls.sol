// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// SWC-104 unchecked low-level call results, and SWC-112 delegatecall.
contract Sender {
    address public owner;
    address public immutable impl;
    event Sent(bool ok);
    error Failed();
    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }
    constructor(address i) { owner = msg.sender; impl = i; }

    // C1: send() result ignored.   C1f: checked.
    function payOut(address to, uint256 amt) external onlyOwner { payable(to).send(amt); }
    function payOutChecked(address to, uint256 amt) external onlyOwner { require(payable(to).send(amt), "send"); }

    // C2: success flag only emitted, never checked.
    function payLogged(address to, uint256 a) external onlyOwner {
        (bool ok, ) = to.call{value: a}("");
        emit Sent(ok);
    }
    // C3: checked with a custom error.
    function forward(address t, bytes calldata data) external onlyOwner {
        (bool ok, bytes memory ret) = t.call(data);
        if (!ok) revert Failed();
        ret;
    }
    // C4: return value discarded entirely.
    function poke(address t) external onlyOwner { t.call(abi.encodeWithSignature("poke()")); }
    // C5: require with message.
    function payReq(address to, uint256 a) external onlyOwner {
        (bool ok, ) = to.call{value: a}("");
        require(ok, "call failed");
    }
    // C6: flag returned to the caller: whether it is checked depends on callers. Ambiguous.
    function tryPay(address to, uint256 a) external onlyOwner returns (bool) {
        (bool ok, ) = to.call{value: a}("");
        return ok;
    }
    // V2: unchecked call in inline assembly.
    function rawPay(address to, uint256 amt) external onlyOwner {
        assembly {
            let ok := call(gas(), to, amt, 0, 0, 0, 0)
        }
    }

    // D2: delegatecall to an immutable implementation fixed at construction.
    function viaImpl(bytes calldata d) external onlyOwner returns (bytes memory) {
        (bool ok, bytes memory r) = impl.delegatecall(d);
        require(ok);
        return r;
    }
}

// D1 (SWC-112): delegatecall to a caller-chosen address.  D1f: owner-only.
contract Proxyish {
    address public owner;
    constructor() { owner = msg.sender; }
    function exec(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
    function execOwner(address target, bytes calldata data) external {
        require(msg.sender == owner);
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
}

// D3 (Parity-style): the delegatecall target lives in storage and its setter has no access control.
contract LibUser {
    address public lib;
    function setLib(address l) external { lib = l; }
    function run(bytes calldata d) external {
        (bool ok, ) = lib.delegatecall(d);
        require(ok);
    }
}
