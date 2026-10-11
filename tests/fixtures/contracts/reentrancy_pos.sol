// SPDX-License-Identifier: Apache-2.0
// Synthetic fixture: POSITIVE reentrancy cases. Markers `@expect RULE` give the ground truth per function.
pragma solidity ^0.8.20;

interface IReceiverR { function onPayout(uint256 amount) external; }

contract ReBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    // classic: value call before zeroing the balance
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        (bool ok, ) = msg.sender.call{value: amount}(""); // @expect SOL-REENTRANCY
        require(ok, "fail");
        balances[msg.sender] = 0;
    }

    // partial withdraw, decrement after the call
    function withdrawPart(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool sent, ) = payable(msg.sender).call{value: amount}(""); // @expect SOL-REENTRANCY
        require(sent);
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    // legacy call.value syntax
    function withdrawLegacy() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call.value(amount)(""); // @expect SOL-REENTRANCY
        require(ok);
        delete balances[msg.sender];
    }

    // interface callback before effect -> NEEDS_REVIEW
    function payoutHook(address to) external {
        uint256 amount = balances[to];
        IReceiverR(to).onPayout(amount); // @expect SOL-REENTRANCY
        balances[to] = 0;
    }
}
