// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.6.0 <0.8.0;

library SafeMathL {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "overflow");
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "underflow");
        return a - b;
    }
}

contract OldSafeToken {
    using SafeMathL for uint256;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public owner;

    constructor() public { owner = msg.sender; }

    function transfer(address to, uint256 amount) external {
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(amount);
        balanceOf[to] = balanceOf[to].add(amount);
    }

    // explicit bound check before the subtraction
    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "low");
        balanceOf[msg.sender] -= amount;
    }

    // local loop counter only
    function count(uint256 n) external pure returns (uint256 c) {
        for (uint256 i = 0; i < n; i++) { c = c.add(1); }
    }
}
