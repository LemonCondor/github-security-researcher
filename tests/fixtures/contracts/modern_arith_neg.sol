// SPDX-License-Identifier: Apache-2.0
// >=0.8: raw arithmetic is checked by the compiler, SOL-LEGACY-ARITH must stay silent.
pragma solidity ^0.8.0;

contract ModernToken {
    mapping(address => uint256) public balanceOf;
    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
