// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract WrapToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) external {
        unchecked { // @expect SOL-UNCHECKED-ARITH
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
        }
    }

    function scale(uint256 a, uint256 b) external pure returns (uint256 r) {
        unchecked { r = a * b; } // @expect SOL-UNCHECKED-ARITH
    }
}
