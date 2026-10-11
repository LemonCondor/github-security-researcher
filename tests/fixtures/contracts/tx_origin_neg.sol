// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract OriginSafe {
    address public owner;
    address public lastOrigin;
    event Called(address origin, address sender);

    constructor() { owner = msg.sender; }

    // EOA-only check, not authorization
    function onlyEOA() external {
        require(tx.origin == msg.sender, "no contracts");
        lastOrigin = msg.sender;
    }

    // tx.origin only logged / stored, never used for a decision
    function log() external {
        emit Called(tx.origin, msg.sender);
        lastOrigin = tx.origin;
    }

    function transferTo(address payable to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        to.transfer(amount);
    }
}
