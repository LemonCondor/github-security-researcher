// SPDX-License-Identifier: Apache-2.0
// Look-alikes of fallback_access_pos.sol that are safe.
pragma solidity ^0.8.20;

// proxy fallback: reads the implementation slot, writes nothing; assembly delegatecall result is switched on
contract MiniProxy {
    address public implementation;
    address public admin;
    constructor(address impl) { implementation = impl; admin = msg.sender; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// receive() bookkeeping user-owned deposits
contract DepositBox {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;
    receive() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }
}

// fallback writing privileged state, but caller-checked
contract GuardedFallback {
    address public owner;
    bool public paused;
    constructor() { owner = msg.sender; }
    fallback() external {
        require(msg.sender == owner, "owner");
        paused = true;
    }
}
