// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

// A1 (SWC-106): anyone can destroy the contract.
contract Killable {
    address public owner;
    constructor() { owner = msg.sender; }
    function kill() public { selfdestruct(payable(msg.sender)); }
}

// A1f: owner check.
contract KillableFixed {
    address public owner;
    constructor() { owner = msg.sender; }
    function kill() public {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}

// A3: anyone can take ownership.  A3f: custom admin modifier with a real check.
contract Admin {
    address public owner;
    mapping(address => bool) public admins;
    modifier onlyAdmin() {
        require(admins[msg.sender], "not admin");
        _;
    }
    function changeOwner(address newOwner) external { owner = newOwner; }
    function changeOwnerSafe(address newOwner) external onlyAdmin { owner = newOwner; }
}

// A4: OpenZeppelin Ownable imported from outside the scanned path.
contract FeeBox is Ownable {
    uint256 public fee;
    constructor() Ownable(msg.sender) {}
    function setFee(uint256 f) external onlyOwner { fee = f; }
}

// A5: a modifier NAMED onlyOwner that checks nothing: vulnerable despite the name.
contract FakeGuard {
    address public owner;
    modifier onlyOwner() { _; }
    function setOwner(address o) external onlyOwner { owner = o; }
}

// A6 (SWC-105): anyone drains the contract.  A7: users withdraw only their own credit (no access control needed).
contract Treasury {
    mapping(address => uint256) public credit;
    function withdrawAll() external {
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok);
    }
    function withdraw() external {
        uint256 c = credit[msg.sender];
        credit[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: c}("");
        require(ok);
    }
}

// A8: user-owned state, benign.
contract Names {
    mapping(address => string) public names;
    function setMyName(string calldata n) external { names[msg.sender] = n; }
}

// A9: free mint (no restriction).  A10: role-gated mint via AccessControl (imported).
contract Coin is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
    function mintGated(address to, uint256 amount) public {
        require(hasRole(MINTER_ROLE, msg.sender), "minter");
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}

// V3: fallback takeover: any call with unknown selector sets the owner.
contract FallbackOwner {
    address public owner;
    fallback() external payable { owner = msg.sender; }
}

// V1: the dangerous text is only in a comment and a string: nothing to report.
contract Commented {
    string public note = "never call selfdestruct(owner) or .call{value: x}";
    function ping() external pure returns (uint256) {
        // selfdestruct(payable(msg.sender));
        return 1;
    }
}
