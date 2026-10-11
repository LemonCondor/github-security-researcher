// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.7.6;

contract OldToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;

    constructor() { owner = msg.sender; }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] -= amount; // @expect SOL-LEGACY-ARITH
        balanceOf[to] += amount;
    }

    function batchMint(address to, uint256 amount, uint256 n) external {
        require(msg.sender == owner);
        totalSupply = totalSupply + amount * n; // @expect SOL-LEGACY-ARITH
        balanceOf[to] += amount * n;
    }
}
