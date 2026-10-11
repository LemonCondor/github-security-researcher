pragma solidity ^0.4.24;

// M1 (SWC-101, BEC-style): unchecked subtraction in 0.4: underflow.  M1f: bound checked first.
contract Token04 {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 value) public returns (bool) {
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }
    function transferChecked(address to, uint256 value) public returns (bool) {
        require(balances[msg.sender] >= value);
        require(balances[to] + value >= balances[to]);
        balances[msg.sender] -= value;
        balances[to] += value;
        return true;
    }
}
