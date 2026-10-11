// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

// T1 (SWC-115): authorisation through tx.origin.  T1f: msg.sender.
contract Wallet {
    address public owner;
    constructor() { owner = msg.sender; }
    function transferTo(address payable dest, uint256 amount) external {
        require(tx.origin == owner, "not owner");
        dest.transfer(amount);
    }
    function transferToFixed(address payable dest, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        dest.transfer(amount);
    }
}

// T2: tx.origin == msg.sender is an EOA check, not authorisation.  T3: tx.origin only logged.
contract Faucet {
    event Drip(address who);
    mapping(address => bool) public got;
    function drip() external {
        require(tx.origin == msg.sender, "no contracts");
        require(!got[msg.sender]);
        got[msg.sender] = true;
        emit Drip(tx.origin);
    }
}

// I1: unprotected initializer of an upgradeable implementation.  I1f: OZ initializer modifier (imported).
contract VaultImpl is Initializable {
    address public owner;
    function initialize(address _owner) public { owner = _owner; }
}
contract VaultImplFixed is Initializable {
    address public owner;
    function initialize(address _owner) public initializer { owner = _owner; }
}

// I2: manual one-time guard.  I3: guard checked but never set (re-initialisable).  I4: internal init.
contract ManualInit {
    bool private initialized;
    address public admin;
    function init(address a) external {
        require(!initialized, "done");
        initialized = true;
        admin = a;
    }
}
contract ForgetfulInit {
    bool private initialized;
    address public admin;
    function init(address a) external {
        require(!initialized, "done");
        admin = a;
    }
}
contract InternalInit {
    address public admin;
    constructor() { _init(msg.sender); }
    function _init(address a) internal { admin = a; }
}
