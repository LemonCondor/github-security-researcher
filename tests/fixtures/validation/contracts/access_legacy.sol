pragma solidity ^0.4.18;

// A2 (SWC-118, Rubixi): the "constructor" has the wrong name, so it is a public function anyone can call.
contract Rubixi {
    address private creator;
    uint private feePercent = 10;
    function DynamicPyramid() public { creator = msg.sender; }
    function collectAllFees() public {
        require(msg.sender == creator);
        creator.transfer(this.balance);
    }
}
