// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract BoundedToken {
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external {
        uint256 bal = balanceOf[msg.sender];
        require(bal >= amount, "insufficient");
        unchecked { balanceOf[msg.sender] = bal - amount; }
        balanceOf[to] += amount;
    }

    function sum(uint256[] calldata xs) external pure returns (uint256 s) {
        for (uint256 i = 0; i < xs.length; ) {
            s += xs[i];
            unchecked { ++i; }
        }
    }

    function burn(uint256 amount) external {
        if (balanceOf[msg.sender] < amount) revert("low");
        unchecked { balanceOf[msg.sender] -= amount; }
    }

    // checked arithmetic outside unchecked: not this rule
    function add(uint256 a, uint256 b) external pure returns (uint256) { return a + b; }
}
