// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Ledger08 {
    mapping(address => uint256) public balances;
    // M2: checked arithmetic (0.8).
    function move(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
    // M3 (SWC-101): unchecked subtraction without a bound check: underflow.
    function moveFast(address to, uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
    // M3f: bound checked before the unchecked block (the addition can still overflow only with
    // an unrealistic total supply: treated as safe).
    function moveFastChecked(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "balance");
        unchecked {
            balances[msg.sender] -= amount;
        }
        balances[to] += amount;
    }
    // M4: loop counter in unchecked.
    function sum(uint256[] calldata xs) external pure returns (uint256 s) {
        for (uint256 i = 0; i < xs.length; ) {
            s += xs[i];
            unchecked { ++i; }
        }
    }
}
