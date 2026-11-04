// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function deal(address who, uint256 newBalance) external;
    function prank(address sender) external;
    function expectRevert() external;
}

/// @dev Minimal test base (no forge-std dependency, so nothing to vendor).
abstract contract Base {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    event log_named_uint(string key, uint256 val);

    function assertEq(uint256 a, uint256 b, string memory what) internal pure {
        require(a == b, what);
    }

    function assertEq(address a, address b, string memory what) internal pure {
        require(a == b, what);
    }

    function assertTrue(bool c, string memory what) internal pure {
        require(c, what);
    }
}
