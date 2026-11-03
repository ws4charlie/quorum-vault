// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Deposit forwarder. Everything it receives or holds can only go to
/// `destination`, which is fixed at construction. No owner, no upgrade path,
/// no function that moves funds anywhere else, so anyone may call the flushes.
contract Forwarder {
    address payable public immutable destination;

    error TransferFailed();

    constructor(address payable destination_) {
        destination = destination_;
    }

    /// @dev Costs more than the 21,000 gas of a plain transfer: a sender must
    /// supply gas for the forwarding call (see docs/measurements/evm.md).
    receive() external payable {
        _flushETH();
    }

    /// @notice Sends the whole ETH balance to destination (ETH that arrived
    /// before this contract existed, or via selfdestruct-style transfers).
    function flushETH() external {
        _flushETH();
    }

    /// @notice Sends this contract's whole balance of `token` to destination.
    /// Works with tokens that return no bool (USDT). Reverts if the token
    /// call fails or returns false.
    function flushTokens(address token) external {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || ret.length < 32) revert TransferFailed();
        uint256 bal = abi.decode(ret, (uint256));
        if (bal == 0) return;
        (ok, ret) = token.call(abi.encodeWithSelector(0xa9059cbb, destination, bal));
        if (!ok) revert TransferFailed();
        if (ret.length != 0 && (ret.length != 32 || abi.decode(ret, (uint256)) != 1)) revert TransferFailed();
    }

    function _flushETH() private {
        uint256 bal = address(this).balance;
        if (bal == 0) return;
        (bool ok,) = destination.call{value: bal}("");
        if (!ok) revert TransferFailed();
    }
}
