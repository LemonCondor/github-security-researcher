// SPDX-License-Identifier: Apache-2.0
// Synthetic upgradeable vault mixing bugs and safe look-alikes (no real protocol).
pragma solidity ^0.8.20;

interface IERC20M {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

abstract contract GuardM {
    uint256 private _locked = 1;
    modifier nonReentrant() { require(_locked == 1); _locked = 2; _; _locked = 1; }
}

contract MixedVault is GuardM {
    address public owner;
    IERC20M public asset;
    uint256 public feeBps;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }

    function initialize(address _asset) external { // @expect SOL-UNPROTECTED-INIT
        owner = msg.sender;
        asset = IERC20M(_asset);
    }

    function deposit(uint256 amount) external nonReentrant {
        require(asset.transferFrom(msg.sender, address(this), amount), "tf");
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    // token transfer before burning shares, no guard
    function redeem(uint256 amount) external {
        require(shares[msg.sender] >= amount, "shares");
        require(asset.transfer(msg.sender, amount), "t"); // @expect SOL-REENTRANCY
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }

    // same, guarded
    function redeemSafe(uint256 amount) external nonReentrant {
        require(shares[msg.sender] >= amount, "shares");
        require(asset.transfer(msg.sender, amount), "t");
        shares[msg.sender] -= amount;
        totalShares -= amount;
    }

    function setFee(uint256 bps) external { // @expect SOL-ACCESS-CONTROL
        feeBps = bps;
    }

    function setFeeOwner(uint256 bps) external onlyOwner { feeBps = bps; }

    function rescueETH(address payable to) external onlyOwner {
        to.call{value: address(this).balance}(""); // @expect SOL-UNCHECKED-CALL
    }

    function emergencyWithdraw() external onlyOwner {
        (bool ok, ) = payable(owner).call{value: address(this).balance}("");
        require(ok);
    }
}
