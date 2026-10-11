// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

abstract contract InitializableN {
    bool private _initialized;
    modifier initializer() {
        require(!_initialized, "already");
        _initialized = true;
        _;
    }
}

contract GuardedInitVault is InitializableN {
    address public owner;
    address public token;
    bool public initialized;
    uint256 public fee;
    address public admin;

    function initialize(address _owner, address _token) external initializer {
        owner = _owner;
        token = _token;
    }

    // manual one-time flag
    function init(uint256 _fee) external {
        require(!initialized, "done");
        initialized = true;
        fee = _fee;
    }

    // zero-address one-time guard on the written slot
    function initializeAdmin(address a) external {
        require(admin == address(0), "set");
        admin = a;
    }

    // internal OZ-style init helper
    function __Vault_init(address o) internal { owner = o; }

    // view helper with an init-like name
    function initialized_() external view returns (bool) { return initialized; }
}
