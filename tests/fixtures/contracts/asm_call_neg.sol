// SPDX-License-Identifier: Apache-2.0
// Look-alikes of asm_call_pos.sol where the assembly call result IS checked.
pragma solidity ^0.8.20;

contract AsmChecked {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    constructor() { owner = msg.sender; }

    function a(address to, uint256 amt) external onlyOwner {
        assembly {
            if iszero(call(gas(), to, amt, 0, 0, 0, 0)) { revert(0, 0) }
        }
    }

    function b(address to, uint256 amt) external onlyOwner {
        assembly {
            let ok := call(gas(), to, amt, 0, 0, 0, 0)
            if iszero(ok) { revert(0, 0) }
        }
    }

    function c(address to, uint256 amt) external onlyOwner returns (bool success) {
        assembly {
            success := call(gas(), to, amt, 0, 0, 0, 0)
        }
    }

    function d(address to, uint256 amt) external onlyOwner {
        bool ok;
        assembly {
            ok := call(gas(), to, amt, 0, 0, 0, 0)
        }
        require(ok, "call failed");
    }

    function e(address t) external view returns (uint256 r) {
        assembly {
            let ok := staticcall(gas(), t, 0, 0, 0, 32)
            switch ok
            case 0 { revert(0, 0) }
            default { r := mload(0) }
        }
    }

    // arithmetic builtins only; the call is in a comment: assembly { let ok := call(gas(), t, 0, 0, 0, 0, 0) }
    function f() external pure returns (uint256 x) {
        assembly { x := add(1, 2) }
    }
}
