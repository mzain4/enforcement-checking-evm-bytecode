// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

contract OpenCaller {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external { owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract GuardedCaller {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external { require(msg.sender == owner); owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract NeighborField {
    address public owner;
    uint96 public counter;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external { counter = uint96(uint160(msg.sender)); }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract ShiftedField {
    uint96 public counter;
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external { owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract OpenParameter {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim(address next) external { owner = next; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract Initialized {
    address public owner;
    bool public initialized;
    constructor() { owner = msg.sender; initialized = true; }
    receive() external payable {}
    function claim() external { require(!initialized); owner = msg.sender; initialized = true; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract TwoCredentials {
    address public owner;
    address public manager;
    constructor() { owner = msg.sender; manager = msg.sender; }
    receive() external payable {}
    function claim() external { owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); require(msg.sender == manager); payable(msg.sender).transfer(address(this).balance); }
}
contract NoSetter {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external {}
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract PartialField {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim() external { assembly { sstore(0, or(and(sload(0), not(255)), and(caller(), 255))) } }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract ExternalSetter {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function claim(address target) external { (bool ok,) = target.call(""); require(ok); owner = msg.sender; }
    function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
}
contract OriginGate {
    uint256 public count;
    uint256 public lastCodeSize;
    function enter() external { require(msg.sender == tx.origin); count++; lastCodeSize = msg.sender.code.length; }
}
contract Forwarder {
    function run(address target) external { (bool ok,) = target.call(abi.encodeWithSignature("enter()")); require(ok); }
}
