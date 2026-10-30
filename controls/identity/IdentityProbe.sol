pragma solidity ^0.8.4;

contract IdentityProbe {
    bool public lastSuccess;
    bytes32 public lastCopy;

    function probe(uint256 forwardedGas, uint256 words, bool enforce) external returns (bool ok) {
        bytes32 copied;
        assembly {
            mstore(0, 0xfeed00000000000000000000000000000000000000000000000000000000beef)
            mstore(128, 0)
            ok := call(forwardedGas, 4, 0, 0, mul(words, 32), 128, mul(words, 32))
            copied := mload(128)
        }
        if (enforce) require(ok, "identity call failed");
        lastSuccess = ok;
        lastCopy = copied;
    }
}
