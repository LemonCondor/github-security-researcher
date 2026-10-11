// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract FixedProxy {
    address public implementation;
    address public owner;

    constructor(address impl) { implementation = impl; owner = msg.sender; }

    modifier onlyOwner() { require(msg.sender == owner); _; }

    // proxy forward: target is a state variable, data from the caller (normal proxy pattern)
    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }

    // admin-only arbitrary delegatecall: by design
    function adminExec(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }

    // parameter used only as data, target is fixed
    function forward(bytes calldata data) external {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok);
    }
}
