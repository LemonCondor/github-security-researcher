pragma solidity ^0.4.24;

// R2: SWC-107 in pre-0.5 syntax (call.value), subtraction after the call.
contract LegacyEtherStore {
    mapping(address => uint256) public balances;
    function depositFunds() public payable { balances[msg.sender] += msg.value; }
    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        require(msg.sender.call.value(_weiToWithdraw)());
        balances[msg.sender] -= _weiToWithdraw;
    }
}
