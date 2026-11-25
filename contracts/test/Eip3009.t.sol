// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Base, Vm} from "./Base.sol";
import {Eip3009Token} from "./mocks/Tokens.sol";

interface VmSign {
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function addr(uint256 privateKey) external returns (address);
    function warp(uint256 ts) external;
    function expectRevert(bytes calldata) external;
}

contract Eip3009Test is Base {
    VmSign constant cheat = VmSign(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant KEY = 0xA11CE;
    address constant PAYEE = address(0xFAC1);
    address constant FACILITATOR = address(0xFAC2);
    Eip3009Token token;
    address payer;

    function setUp() public {
        token = new Eip3009Token("USDC");
        payer = cheat.addr(KEY);
        token.mint(payer, 1_000_000);
        cheat.warp(1_000);
    }

    function _digest(address from, address to, uint256 value, uint256 after_, uint256 before_, bytes32 nonce) private view returns (bytes32) {
        bytes32 sh = keccak256(abi.encode(token.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), from, to, value, after_, before_, nonce));
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), sh));
    }

    function testTransferWithAuthorizationMovesAndRecordsNonce() public {
        bytes32 n = bytes32(uint256(1));
        (uint8 v, bytes32 r, bytes32 s) = cheat.sign(KEY, _digest(payer, PAYEE, 250_000, 0, 2_000, n));
        vm.prank(FACILITATOR);
        token.transferWithAuthorization(payer, PAYEE, 250_000, 0, 2_000, n, v, r, s);
        assertEq(token.balanceOf(PAYEE), 250_000, "payee");
        assertEq(token.balanceOf(payer), 750_000, "payer");
        assertTrue(token.authorizationState(payer, n), "nonce used");
    }

    function testNonceIsUsedOnce() public {
        bytes32 n = bytes32(uint256(2));
        (uint8 v, bytes32 r, bytes32 s) = cheat.sign(KEY, _digest(payer, PAYEE, 1, 0, 2_000, n));
        token.transferWithAuthorization(payer, PAYEE, 1, 0, 2_000, n, v, r, s);
        cheat.expectRevert("FiatTokenV2: authorization is used or canceled");
        token.transferWithAuthorization(payer, PAYEE, 1, 0, 2_000, n, v, r, s);
    }

    function testWindowBoundsAreExclusive() public {
        bytes32 n = bytes32(uint256(3));
        (uint8 v, bytes32 r, bytes32 s) = cheat.sign(KEY, _digest(payer, PAYEE, 1, 1_000, 2_000, n));
        cheat.expectRevert("FiatTokenV2: authorization is not yet valid");
        token.transferWithAuthorization(payer, PAYEE, 1, 1_000, 2_000, n, v, r, s); // block.timestamp == validAfter
        cheat.warp(2_000);
        cheat.expectRevert("FiatTokenV2: authorization is expired");
        token.transferWithAuthorization(payer, PAYEE, 1, 1_000, 2_000, n, v, r, s); // block.timestamp == validBefore
    }

    function testWrongSignerAndTamperedValueFail() public {
        bytes32 n = bytes32(uint256(4));
        (uint8 v, bytes32 r, bytes32 s) = cheat.sign(0xB0B, _digest(payer, PAYEE, 1, 0, 2_000, n));
        cheat.expectRevert("FiatTokenV2: invalid signature");
        token.transferWithAuthorization(payer, PAYEE, 1, 0, 2_000, n, v, r, s);
        (v, r, s) = cheat.sign(KEY, _digest(payer, PAYEE, 1, 0, 2_000, n));
        cheat.expectRevert("FiatTokenV2: invalid signature");
        token.transferWithAuthorization(payer, PAYEE, 2, 0, 2_000, n, v, r, s);
    }

    function testHighSIsRefused() public {
        bytes32 n = bytes32(uint256(5));
        (uint8 v, bytes32 r, bytes32 s) = cheat.sign(KEY, _digest(payer, PAYEE, 1, 0, 2_000, n));
        bytes32 hi = bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s));
        cheat.expectRevert("ECRecover: invalid signature 's' value");
        token.transferWithAuthorization(payer, PAYEE, 1, 0, 2_000, n, v == 27 ? 28 : 27, r, hi);
    }
}
