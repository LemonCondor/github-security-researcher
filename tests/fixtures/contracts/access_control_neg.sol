// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

contract GuardedAdmin {
    address public owner;
    address public pendingOwner;
    address public implementation;
    mapping(address => uint256) public balanceOf;
    mapping(address => string) public names;
    mapping(address => bool) public minters;
    uint256 public totalSupply;
    uint256 public price = 1 ether;

    error NotOwner();

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    modifier gated() { if (msg.sender != owner) revert NotOwner(); _; }

    constructor() { owner = msg.sender; }

    function setOwner(address newOwner) external onlyOwner { pendingOwner = newOwner; }

    // two-step ownership: claim checks pendingOwner
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "pending");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    // custom-named modifier: recognised from its body
    function upgradeTo(address impl) external gated { implementation = impl; }

    // inline if/revert check
    function kill() external {
        if (msg.sender != owner) revert NotOwner();
        selfdestruct(payable(owner));
    }

    // role mapping on msg.sender
    function mint(address to, uint256 amount) external {
        require(minters[msg.sender], "minter");
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // paid public mint (sale) is public by design
    function mintPublic() external payable {
        require(msg.value >= price, "price");
        balanceOf[msg.sender] += 1;
        totalSupply += 1;
    }

    // user-owned data, not privileged
    function setName(string calldata n) external { names[msg.sender] = n; }

    // internal setter: not an entry point
    function _setOwner(address o) internal { owner = o; }

    // view
    function getOwner() external view returns (address) { return owner; }
}
