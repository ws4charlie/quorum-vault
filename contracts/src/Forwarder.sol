// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface IDestination {
    function destination() external view returns (address);
}

/// @notice Deposit forwarder. It stays on its address. Everything it holds can only go to
/// the factory's current `destination`, read at flush time; the forwarder stores no
/// destination of its own. No owner, no upgrade path, no delegatecall, no opcode that removes the contract.
///
/// Init code has no arguments (`factory` is the deployer), so the address depends on
/// the factory and the salt only, never on the destination.
contract Forwarder {
    address public immutable factory;

    /// @notice One event per flush that moved funds. `token` is zero for ETH. Accounting
    /// reads this (not the deposits it expected), because a flush moves the whole balance.
    event Swept(address indexed token, uint256 amount);

    error SweepFrozen();
    error TransferFailed();

    constructor() {
        factory = msg.sender;
    }

    /// @dev Accepts ETH and does nothing else, so it costs almost no gas: a 2300-gas
    /// `transfer()` works. A transaction with a limit of exactly 21,000 does not (the
    /// code still has to run); see docs/measurements/evm.md for the minimum.
    receive() external payable {}

    /// @notice Sends the whole ETH balance to the factory's destination. Reverts
    /// SweepFrozen() when the destination is zero, so a caller can never record a
    /// sweep that moved nothing.
    function flushETH() external {
        address payable dest = _destination();
        uint256 bal = address(this).balance;
        if (bal == 0) return;
        (bool ok,) = dest.call{value: bal}("");
        if (!ok) revert TransferFailed();
        emit Swept(address(0), bal);
    }

    /// @notice Sends this contract's whole balance of `token` to the destination. Works
    /// with tokens that return no bool (USDT). Reverts if the token call fails or
    /// returns false, or when frozen.
    function flushTokens(address token) external {
        address dest = _destination();
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || ret.length < 32) revert TransferFailed();
        uint256 bal = abi.decode(ret, (uint256));
        if (bal == 0) return;
        (ok, ret) = token.call(abi.encodeWithSelector(0xa9059cbb, dest, bal));
        if (!ok) revert TransferFailed();
        if (ret.length != 0 && (ret.length != 32 || abi.decode(ret, (uint256)) != 1)) revert TransferFailed();
        emit Swept(token, bal);
    }

    function _destination() private view returns (address payable dest) {
        dest = payable(IDestination(factory).destination());
        if (dest == address(0)) revert SweepFrozen();
    }
}
