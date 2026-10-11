// SPDX-License-Identifier: Apache-2.0
// Regression (validation v1 FN V2, SWC-104): low-level calls in inline assembly whose success flag is ignored.
pragma solidity ^0.8.20;

contract AsmSender {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    constructor() { owner = msg.sender; }

    function rawPay(address to, uint256 amt) external onlyOwner {
        assembly {
            let ok := call(gas(), to, amt, 0, 0, 0, 0) // @expect SOL-UNCHECKED-CALL
        }
    }

    function rawPayAssign(address to, uint256 amt) external onlyOwner {
        bool sent;
        assembly {
            sent := call(gas(), to, amt, 0, 0, 0, 0) // @expect SOL-UNCHECKED-CALL
        }
    }

    // explicit discard: reported as NEEDS_REVIEW (often deliberate, e.g. best-effort refunds)
    function rawPayPop(address to, uint256 amt) external onlyOwner {
        assembly {
            pop(call(gas(), to, amt, 0, 0, 0, 0)) // @expect SOL-UNCHECKED-CALL
        }
    }
}
