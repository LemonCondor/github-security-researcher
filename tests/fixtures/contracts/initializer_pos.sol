// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract OpenInitVault {
    address public owner;
    address public token;
    uint256 public fee;

    function initialize(address _owner, address _token) external { // @expect SOL-UNPROTECTED-INIT
        owner = _owner;
        token = _token;
    }

    function initializeV2(uint256 _fee) public { // @expect SOL-UNPROTECTED-INIT
        fee = _fee;
    }
}
