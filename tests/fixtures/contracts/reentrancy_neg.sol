// SPDX-License-Identifier: Apache-2.0
// Synthetic fixture: NEGATIVE (safe look-alike) reentrancy cases. No marker = no finding expected.
pragma solidity ^0.8.20;

abstract contract SafeGuardN {
    uint256 private _status = 1;
    modifier nonReentrant() {
        require(_status == 1, "reentrant");
        _status = 2;
        _;
        _status = 1;
    }
}

contract SafeBank is SafeGuardN {
    mapping(address => uint256) public balances;
    uint256 public withdrawCount;

    function deposit() external payable { balances[msg.sender] += msg.value; }

    // CEI respected: effect before interaction
    function withdrawCEI() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
    }

    // call before write, but guarded by nonReentrant
    function withdrawGuarded() external nonReentrant {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }

    // transfer (2300 gas stipend) before write: out of scope by design
    function withdrawTransfer() external {
        uint256 amount = balances[msg.sender];
        payable(msg.sender).transfer(amount);
        balances[msg.sender] = 0;
    }

    // write after the call touches a variable never read before the call
    function withdrawCounter() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        withdrawCount += 1;
    }

    // view function making a staticcall
    function peek(address t) external view returns (bool ok) {
        (ok, ) = t.staticcall("");
    }

    // internal helper: not an entry point
    function _pay(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
        balances[to] = 0;
    }
}
