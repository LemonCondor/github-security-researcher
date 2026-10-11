// Regression (validation v1 FN A2, SWC-118): before 0.4.22 the constructor is the function named like the
// contract. A misnamed one is a public function; here it writes the address later used for authorization.
pragma solidity ^0.4.18;

contract Pyramid {
    address private creator;
    function DynamicPyramid() public { // @expect SOL-ACCESS-CONTROL
        creator = msg.sender;
    }
    function collectAllFees() public {
        require(msg.sender == creator);
        creator.transfer(this.balance);
    }
}

contract Wallet {
    address keeper;
    function Walet() { // @expect SOL-ACCESS-CONTROL
        keeper = msg.sender;
    }
    function payTo(address to, uint256 amount) {
        if (msg.sender != keeper) revert();
        to.transfer(amount);
    }
}
