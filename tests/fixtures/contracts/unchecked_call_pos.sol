// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract SloppyCaller {
    address public owner;
    event Sent(bool ok);

    constructor() { owner = msg.sender; }

    function pay(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        to.call{value: amount}(""); // @expect SOL-UNCHECKED-CALL
    }

    function paySend(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        to.send(amount); // @expect SOL-UNCHECKED-CALL
    }

    function payOmitted(address to, bytes calldata data) external {
        require(msg.sender == owner);
        (, bytes memory ret) = to.call(data); // @expect SOL-UNCHECKED-CALL
        ret;
    }

    // flag captured but only emitted, never checked
    function payLogged(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        (bool ok, ) = to.call{value: amount}(""); // @expect SOL-UNCHECKED-CALL
        emit Sent(ok);
    }
}
