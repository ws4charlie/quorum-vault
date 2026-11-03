// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Forwarder} from "./Forwarder.sol";

/// @notice Deploys Forwarders with CREATE2. `destination` is part of every
/// forwarder's init code, so a deposit address commits to it: a different
/// destination (or factory) yields a different address for the same salt.
contract ForwarderFactory {
    address payable public immutable destination;

    constructor(address payable destination_) {
        destination = destination_;
    }

    /// @notice Address the forwarder for `salt` has, or will have once deployed.
    function predict(bytes32 salt) public view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(_initCode())));
        return address(uint160(uint256(h)));
    }

    /// @notice Deploys the forwarder for `salt` if it is not deployed yet, then
    /// flushes ETH (including ETH sent before deployment) and each token in
    /// `tokens`, in one transaction. On an already deployed salt it just flushes.
    function deployAndFlush(bytes32 salt, address[] calldata tokens) external returns (address fwd) {
        fwd = predict(salt);
        if (fwd.code.length == 0) {
            Forwarder f = new Forwarder{salt: salt}(destination);
            require(address(f) == fwd, "address mismatch");
        }
        Forwarder(payable(fwd)).flushETH();
        for (uint256 i = 0; i < tokens.length; i++) {
            Forwarder(payable(fwd)).flushTokens(tokens[i]);
        }
    }

    function _initCode() private view returns (bytes memory) {
        return abi.encodePacked(type(Forwarder).creationCode, abi.encode(destination));
    }
}
