// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract CarefulCaller {
    address public owner;
    error CallFailed();

    constructor() { owner = msg.sender; }

    function payRequire(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        (bool success, ) = to.call{value: amount}("");
        require(success, "call failed");
    }

    function payIf(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert CallFailed();
    }

    function paySendChecked(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        require(to.send(amount), "send failed");
    }

    function payReturn(address to, bytes calldata data) external returns (bool) {
        require(msg.sender == owner);
        (bool ok, ) = to.call(data);
        return ok;
    }

    function payAssign(address payable to, uint256 amount) external {
        require(msg.sender == owner);
        bool ok;
        (ok, ) = to.call{value: amount}("");
        require(ok);
    }
}
