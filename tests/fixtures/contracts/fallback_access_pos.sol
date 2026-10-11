// SPDX-License-Identifier: Apache-2.0
// Regression (validation v1 FN V3): fallback()/receive() are entry points; writing authority state there is
// an ownership takeover by any caller.
pragma solidity ^0.8.20;

contract FallbackTakeover {
    address public owner;
    uint256 public hits;
    fallback() external payable { // @expect SOL-ACCESS-CONTROL
        hits += 1;
        owner = msg.sender;
    }
}

contract ReceiveAdmin {
    address public admin;
    receive() external payable { // @expect SOL-ACCESS-CONTROL
        admin = msg.sender;
    }
}

contract FallbackKill {
    address public owner;
    constructor() { owner = msg.sender; }
    fallback() external { // @expect SOL-ACCESS-CONTROL
        selfdestruct(payable(msg.sender));
    }
}
