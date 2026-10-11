// SPDX-License-Identifier: Apache-2.0
// Real bugs this syntax-only engine is KNOWN to miss (`@known-fn RULE`). Kept to measure recall honestly.
pragma solidity ^0.8.20;

contract LimitsBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public unlockTime;

    modifier onlyAfterDelay() { require(block.timestamp >= unlockTime); _; }

    // effect hidden in an internal helper: intra-procedural analysis does not follow it
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}(""); // @known-fn SOL-REENTRANCY
        require(ok);
        _clear(msg.sender);
    }

    function _clear(address a) internal { balances[a] = 0; }

    // `only*` modifier whose body does not check msg.sender: judged by body, not name -> detected
    function setOwner(address o) external onlyAfterDelay { // @expect SOL-ACCESS-CONTROL
        owner = o;
    }
}
