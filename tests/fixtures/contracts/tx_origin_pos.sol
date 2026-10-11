// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract OriginWallet {
    address public owner;
    mapping(address => bool) public trusted;
    uint256 public counter;

    constructor() { owner = msg.sender; }

    modifier onlyOriginOwner() {
        require(tx.origin == owner, "not owner"); // @expect SOL-TX-ORIGIN
        _;
    }

    function transferTo(address payable to, uint256 amount) external {
        require(tx.origin == owner, "not owner"); // @expect SOL-TX-ORIGIN
        to.transfer(amount);
    }

    function trustedAction() external {
        if (!trusted[tx.origin]) revert("untrusted"); // @expect SOL-TX-ORIGIN
        counter += 1;
    }

    function sweep(address payable to) external onlyOriginOwner { to.transfer(address(this).balance); }
}
