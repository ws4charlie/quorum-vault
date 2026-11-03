// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Base} from "./Base.sol";
import {Forwarder} from "../src/Forwarder.sol";
import {ForwarderFactory} from "../src/ForwarderFactory.sol";
import {UsdtLike, BoolToken, FalseToken} from "./mocks/Tokens.sol";

contract ForwarderTest is Base {
    address payable constant DEST = payable(address(0xD357));
    address constant ATTACKER = address(0xBAD);
    ForwarderFactory factory;

    function setUp() public {
        factory = new ForwarderFactory(DEST);
    }

    function _one(address a) private pure returns (address[] memory t) {
        t = new address[](1);
        t[0] = a;
    }

    function testAddressMatchesPrediction() public {
        bytes32 salt = keccak256("alice/0");
        address predicted = factory.predict(salt);
        assertTrue(predicted.code.length == 0, "not deployed yet");
        address got = factory.deployAndFlush(salt, new address[](0));
        assertEq(got, predicted, "deployed != predicted");
        assertTrue(predicted.code.length > 0, "deployed");
        assertEq(Forwarder(payable(predicted)).destination(), DEST, "destination");
        // Fixed vector the Go code must reproduce (see evm_test.go TestPredictVector).
        emit log_named_uint("predict(keccak(alice/0)) factory-relative ok", 1);
    }

    function testEthSentBeforeDeploymentIsSwept() public {
        bytes32 salt = keccak256("bob/7");
        address predicted = factory.predict(salt);
        vm.deal(predicted, 3 ether);
        uint256 before_ = DEST.balance;
        factory.deployAndFlush(salt, new address[](0));
        assertEq(DEST.balance - before_, 3 ether, "swept");
        assertEq(predicted.balance, 0, "forwarder empty");
    }

    function testEthAfterDeploymentForwardsOnReceipt() public {
        bytes32 salt = keccak256("carol/1");
        address f = factory.deployAndFlush(salt, new address[](0));
        vm.deal(address(this), 5 ether);
        uint256 before_ = DEST.balance;
        (bool ok,) = f.call{value: 2 ether}("");
        assertTrue(ok, "send");
        assertEq(DEST.balance - before_, 2 ether, "forwarded");
        assertEq(f.balance, 0, "forwarder empty");
    }

    function testUsdtStyleTokenSwept() public {
        UsdtLike usdt = new UsdtLike();
        bytes32 salt = keccak256("dave/2");
        address predicted = factory.predict(salt);
        usdt.mint(predicted, 1_000_000);
        factory.deployAndFlush(salt, _one(address(usdt)));
        assertEq(usdt.balanceOf(DEST), 1_000_000, "usdt at destination");
        assertEq(usdt.balanceOf(predicted), 0, "forwarder empty");
    }

    function testBoolTokenSwept() public {
        BoolToken t = new BoolToken();
        bytes32 salt = keccak256("erin/3");
        address predicted = factory.predict(salt);
        t.mint(predicted, 42);
        factory.deployAndFlush(salt, _one(address(t)));
        assertEq(t.balanceOf(DEST), 42, "token at destination");
    }

    function testFalseReturningTokenReverts() public {
        FalseToken t = new FalseToken();
        bytes32 salt = keccak256("frank/4");
        t.mint(factory.predict(salt), 1);
        vm.expectRevert();
        factory.deployAndFlush(salt, _one(address(t)));
    }

    function testNonContractTokenReverts() public {
        bytes32 salt = keccak256("gina/5");
        vm.expectRevert();
        factory.deployAndFlush(salt, _one(address(0x1234)));
    }

    function testRedeployOnDeployedSaltFlushes() public {
        UsdtLike usdt = new UsdtLike();
        bytes32 salt = keccak256("heidi/6");
        address f = factory.deployAndFlush(salt, new address[](0));
        usdt.mint(f, 9);
        address again = factory.deployAndFlush(salt, _one(address(usdt)));
        assertEq(again, f, "same address");
        assertEq(usdt.balanceOf(DEST), 9, "flushed on second call");
    }

    function testAnyoneCanFlushButFundsOnlyReachDestination() public {
        UsdtLike usdt = new UsdtLike();
        bytes32 salt = keccak256("ivan/8");
        address f = factory.deployAndFlush(salt, new address[](0));
        usdt.mint(f, 77);
        vm.deal(f, 1 ether);
        vm.prank(ATTACKER);
        Forwarder(payable(f)).flushTokens(address(usdt));
        vm.prank(ATTACKER);
        Forwarder(payable(f)).flushETH();
        assertEq(usdt.balanceOf(ATTACKER), 0, "attacker got no tokens");
        assertEq(ATTACKER.balance, 0, "attacker got no ETH");
        assertEq(usdt.balanceOf(DEST), 77, "tokens at destination");
        assertEq(DEST.balance, 1 ether, "ETH at destination");
    }

    function testDestinationCommittedInAddress() public {
        bytes32 salt = keccak256("judy/9");
        ForwarderFactory evil = new ForwarderFactory(payable(ATTACKER));
        assertTrue(evil.predict(salt) != factory.predict(salt), "other destination, other address");
        // Same factory code and salt but another destination cannot reach a deposit address.
        vm.deal(factory.predict(salt), 1 ether);
        evil.deployAndFlush(salt, new address[](0));
        assertEq(factory.predict(salt).balance, 1 ether, "deposit address untouched by the evil factory");
    }

    function testFlushZeroBalanceIsNoop() public {
        UsdtLike usdt = new UsdtLike();
        address f = factory.deployAndFlush(keccak256("kim/10"), new address[](0));
        Forwarder(payable(f)).flushTokens(address(usdt));
        Forwarder(payable(f)).flushETH();
    }

    // Known limit (documented, not fixed): after deployment a plain ETH send
    // that gives the receiver only the 21,000-gas base reverts.
    function testPlainSendWithFixedGasReverts() public {
        address f = factory.deployAndFlush(keccak256("leo/11"), new address[](0));
        vm.deal(address(this), 1 ether);
        (bool ok,) = f.call{value: 1, gas: 2300}("");
        assertTrue(!ok, "2300-gas send must fail");
        // Smallest forwarded gas that works.
        uint256 lo = 2300;
        uint256 hi = 100_000;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            (bool ok2,) = f.call{value: 1, gas: mid}("");
            if (ok2) hi = mid;
            else lo = mid + 1;
        }
        emit log_named_uint("min gas forwarded to receive()", lo);
    }

    function testGasDeployAndFlush() public {
        UsdtLike usdt = new UsdtLike();
        bytes32 salt = keccak256("mia/12");
        address predicted = factory.predict(salt);
        usdt.mint(predicted, 5);
        vm.deal(predicted, 1 ether);
        address[] memory toks = _one(address(usdt));
        uint256 g = gasleft();
        factory.deployAndFlush(salt, toks);
        emit log_named_uint("gas deployAndFlush (deploy + ETH + 1 token)", g - gasleft());

        usdt.mint(predicted, 5);
        vm.deal(predicted, 1 ether);
        g = gasleft();
        factory.deployAndFlush(salt, toks);
        emit log_named_uint("gas flush alone via factory (ETH + 1 token)", g - gasleft());

        usdt.mint(predicted, 5);
        g = gasleft();
        Forwarder(payable(predicted)).flushTokens(address(usdt));
        emit log_named_uint("gas flushTokens direct (1 token)", g - gasleft());

        vm.deal(predicted, 1 ether);
        g = gasleft();
        Forwarder(payable(predicted)).flushETH();
        emit log_named_uint("gas flushETH direct", g - gasleft());
    }
}
