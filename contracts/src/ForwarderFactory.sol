// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Forwarder} from "./Forwarder.sol";

/// @notice Deploys Forwarders with CREATE2 and owns the one destination every
/// forwarder pays to. `admin` (meant to be a cold-key address) is the only account
/// that can change it; destination zero freezes all sweeping (funds stay where they are).
contract ForwarderFactory {
    address public destination;
    address public admin;
    address public pendingAdmin;

    event DestinationChanged(address indexed previous, address indexed current);
    event AdminTransferStarted(address indexed admin, address indexed pendingAdmin);
    event AdminChanged(address indexed previous, address indexed current);

    error NotAdmin();
    error NotPendingAdmin();
    error ZeroAddress();
    error SweepFrozen();

    constructor(address destination_, address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        destination = destination_;
        admin = admin_;
        emit DestinationChanged(address(0), destination_);
        emit AdminChanged(address(0), admin_);
    }

    /// @notice Zero is allowed: it freezes sweeping.
    function setDestination(address newDestination) external {
        if (msg.sender != admin) revert NotAdmin();
        emit DestinationChanged(destination, newDestination);
        destination = newDestination;
    }

    /// @notice Step 1 of 2: nominate a new admin. It has no power until it accepts.
    function transferAdmin(address newAdmin) external {
        if (msg.sender != admin) revert NotAdmin();
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    /// @notice Step 2 of 2: the nominated admin accepts; the old admin loses power.
    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotPendingAdmin();
        emit AdminChanged(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    /// @notice Address of the forwarder for `salt`. Independent of `destination`.
    function predict(bytes32 salt) public view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(type(Forwarder).creationCode)));
        return address(uint160(uint256(h)));
    }

    /// @notice Deploys the forwarder for `salt` if needed, then flushes ETH and each
    /// token, in one transaction. Reverts SweepFrozen() when frozen: nothing deploys, nothing moves.
    function deployAndFlush(bytes32 salt, address[] calldata tokens) external returns (address fwd) {
        if (destination == address(0)) revert SweepFrozen();
        fwd = _deployAndFlush(salt, tokens);
    }

    /// @notice Same for many salts with one token list.
    function deployAndFlushMany(bytes32[] calldata salts, address[] calldata tokens) external {
        if (destination == address(0)) revert SweepFrozen();
        for (uint256 i = 0; i < salts.length; i++) {
            _deployAndFlush(salts[i], tokens);
        }
    }

    function _deployAndFlush(bytes32 salt, address[] calldata tokens) private returns (address fwd) {
        fwd = predict(salt);
        if (fwd.code.length == 0) {
            Forwarder f = new Forwarder{salt: salt}();
            require(address(f) == fwd, "address mismatch");
        }
        Forwarder(payable(fwd)).flushETH();
        for (uint256 i = 0; i < tokens.length; i++) {
            Forwarder(payable(fwd)).flushTokens(tokens[i]);
        }
    }
}
