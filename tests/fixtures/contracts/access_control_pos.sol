// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract OpenAdmin {
    address public owner;
    address public implementation;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    mapping(address => bool) public admins;
    bool public paused;

    constructor() { owner = msg.sender; }

    function setOwner(address newOwner) external { // @expect SOL-ACCESS-CONTROL
        owner = newOwner;
    }

    function mint(address to, uint256 amount) public { // @expect SOL-ACCESS-CONTROL
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function upgradeTo(address impl) external { // @expect SOL-ACCESS-CONTROL
        implementation = impl;
    }

    function kill() external { // @expect SOL-ACCESS-CONTROL
        selfdestruct(payable(msg.sender));
    }

    function drain(address payable to) external { // @expect SOL-ACCESS-CONTROL
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok);
    }

    // a balance check on msg.sender is NOT access control
    function addAdmin(address who) external { // @expect SOL-ACCESS-CONTROL
        require(balanceOf[msg.sender] > 0, "holder");
        admins[who] = true;
    }

    // EOA check is not authorization
    function pause() external { // @expect SOL-ACCESS-CONTROL
        require(tx.origin == msg.sender, "eoa");
        paused = true;
    }
}
