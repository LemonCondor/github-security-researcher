// Look-alikes of legacy_ctor_pos.sol that are safe.
pragma solidity ^0.4.18;

// correctly named legacy constructor: not an entry point
contract Rubix2 {
    address private creator;
    function Rubix2() public {
        creator = msg.sender;
    }
    function collectAllFees() public {
        require(msg.sender == creator);
        creator.transfer(this.balance);
    }
    function changeCreator(address c) public {
        require(msg.sender == creator);
        creator = c;
    }
}

// msg.sender stored but never used to authorize anything (anti-repeat `!=` is not authorization)
contract Turns {
    address public lastPlayer;
    function play() public payable {
        require(msg.value == 1 ether);
        lastPlayer = msg.sender;
    }
    function playAgain() public payable {
        require(msg.sender != lastPlayer);
        lastPlayer = msg.sender;
    }
}
