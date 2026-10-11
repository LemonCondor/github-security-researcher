pragma solidity >=0.7.0 <0.9.0;

// M5: the pragma admits both unchecked (0.7) and checked (0.8) compilers: outcome depends on the build.
contract RangeCounter {
    uint256 public total;
    function add(uint256 x) external { total += x; }
}
