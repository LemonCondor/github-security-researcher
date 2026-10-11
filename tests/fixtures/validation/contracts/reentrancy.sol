// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// R1: DAO-style withdraw (SWC-107), value sent before the balance is cleared.
contract DaoBank {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}

// R1f: same contract, checks-effects-interactions.
contract DaoBankFixed {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
}

// R3: call before write, but a locally defined mutex guard protects it.
contract GuardedBank {
    mapping(address => uint256) public credit;
    bool private locked;
    modifier lock() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }
    function claim(uint256 amount) external lock {
        require(credit[msg.sender] >= amount);
        (bool sent, ) = payable(msg.sender).call{value: amount}("");
        require(sent);
        credit[msg.sender] -= amount;
    }
}

interface IERC20Like { function transfer(address to, uint256 v) external returns (bool); }

// R4: ERC20 transfer before clearing deposits: reentrancy only if the token has hooks (ERC777). Ambiguous.
contract TokenVault {
    IERC20Like public token;
    mapping(address => uint256) public deposits;
    function withdrawTokens() external {
        uint256 amt = deposits[msg.sender];
        require(token.transfer(msg.sender, amt));
        deposits[msg.sender] = 0;
    }
}

// R5: interaction last; the only write after the call is to unrelated, unread bookkeeping.
contract Payout {
    mapping(address => uint256) public owed;
    uint256 public lastPayout;
    function pay() external {
        uint256 v = owed[msg.sender];
        owed[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: v}("");
        require(ok);
        lastPayout = block.timestamp;
    }
}

// R6: cross-function reentrancy: withdraw is CEI-like on `shares` but `transferShares` can be re-entered
// during the call because `paid` is updated after it (SWC-107 cross-function). Out of scope of single-function rules.
contract SharePool {
    mapping(address => uint256) public shares;
    mapping(address => bool) public paid;
    function transferShares(address to, uint256 n) external {
        require(!paid[msg.sender] && shares[msg.sender] >= n);
        shares[msg.sender] -= n;
        shares[to] += n;
    }
    function cashOut() external {
        require(!paid[msg.sender]);
        (bool ok, ) = msg.sender.call{value: shares[msg.sender] * 1 gwei}("");
        require(ok);
        paid[msg.sender] = true;
    }
}

// R7: transfer() forwards 2300 gas: not re-entrant in practice (bad practice for other reasons).
contract StipendBank {
    mapping(address => uint256) public bal;
    function out() external {
        uint256 a = bal[msg.sender];
        payable(msg.sender).transfer(a);
        bal[msg.sender] = 0;
    }
}
