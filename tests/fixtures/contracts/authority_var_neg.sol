// SPDX-License-Identifier: Apache-2.0
// Look-alikes of authority_var_pos.sol that are safe.
pragma solidity ^0.8.20;

contract LibFixed {
    address public lib;
    address public keeper;
    constructor(address l) { lib = l; keeper = msg.sender; }
    function setLib(address l) external {
        require(msg.sender == keeper, "keeper");
        lib = l;
    }
    function run(bytes calldata d) external {
        (bool ok, ) = lib.delegatecall(d);
        require(ok);
    }
}

// lastCaller is recorded, never used for authorization or as a call target
contract Registry {
    address public lastCaller;
    mapping(address => uint256) public counts;
    function ping() external {
        lastCaller = msg.sender;
        counts[msg.sender] += 1;
    }
}

// beneficiary rotates itself: guarded by the same comparison
contract Stream {
    address public beneficiary;
    constructor(address b) { beneficiary = b; }
    function setBeneficiary(address b) external {
        if (msg.sender != beneficiary) revert();
        beneficiary = b;
    }
    function claim() external {
        require(msg.sender == beneficiary, "beneficiary");
        payable(beneficiary).transfer(1);
    }
}

// two-phase auction: highestBidder is a plain record, `!=` in require is not an authorization
contract Auction {
    address public highestBidder;
    uint256 public highestBid;
    function bid() external payable {
        require(msg.sender != highestBidder, "already");
        require(msg.value > highestBid, "low");
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
