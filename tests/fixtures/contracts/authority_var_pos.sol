// SPDX-License-Identifier: Apache-2.0
// Regression (validation v1 FN D3, Parity-style): a state address whose role is visible only from its USE
// (delegatecall target, or compared with msg.sender elsewhere) is set by an unprotected function.
pragma solidity ^0.8.20;

contract LibConsumer {
    address public lib;
    function setLib(address l) external { // @expect SOL-ACCESS-CONTROL
        lib = l;
    }
    function run(bytes calldata d) external {
        (bool ok, ) = lib.delegatecall(d);
        require(ok);
    }
}

contract Fund {
    address public manager;
    function setManager(address m) external { // @expect SOL-ACCESS-CONTROL
        manager = m;
    }
    function payOut(address payable to, uint256 a) external {
        require(msg.sender == manager, "manager");
        to.transfer(a);
    }
}
