// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// O1 (SWC-120): predictable randomness.  O2 (SWC-121): signature replay (no nonce, no chain id).
// Both are real vulnerabilities that a single-function syntactic engine is NOT expected to find.
contract Lottery {
    address[] public players;
    function enter() external payable { require(msg.value == 1 ether); players.push(msg.sender); }
    function pick() external {
        uint256 i = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao))) % players.length;
        (bool ok, ) = payable(players[i]).call{value: address(this).balance}("");
        require(ok);
        delete players;
    }
}

contract Voucher {
    address public signer;
    mapping(address => uint256) public claimed;
    constructor(address s) { signer = s; }
    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        require(ecrecover(h, v, r, s) == signer, "sig");
        claimed[msg.sender] += amount;
    }
}
