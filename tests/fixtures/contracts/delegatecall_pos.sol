// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract OpenExecutor {
    address public owner;
    constructor() { owner = msg.sender; }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data); // @expect SOL-DELEGATECALL-PARAM
        require(ok);
        return ret;
    }

    function run(address lib) public {
        (bool ok, ) = address(lib).delegatecall(abi.encodeWithSignature("go()")); // @expect SOL-DELEGATECALL-PARAM
        require(ok);
    }
}
