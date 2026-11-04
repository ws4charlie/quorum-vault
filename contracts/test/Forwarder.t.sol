// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// Run with `forge test --isolate` (each top-level call is its own transaction).

import {Base, Vm} from "./Base.sol";
import {Forwarder} from "../src/Forwarder.sol";
import {ForwarderFactory} from "../src/ForwarderFactory.sol";
import {UsdtLike, BoolToken, FalseToken, TransferSender, ReentrantToken} from "./mocks/Tokens.sol";

contract ForwarderTest is Base {
    address constant DEST = address(0xD357);
    address constant DEST2 = address(0xD358);
    address constant ADMIN = address(0xAD41);
    address constant ADMIN2 = address(0xAD42);
    address constant GUARDIAN = address(0x6A4D);
    address constant GUARDIAN2 = address(0x6A4E);
    address constant ATTACKER = address(0xBAD);
    ForwarderFactory factory;
    UsdtLike usdt;

    function setUp() public {
        factory = new ForwarderFactory(DEST, ADMIN, GUARDIAN);
        usdt = new UsdtLike();
    }

    function _one(address a) private pure returns (address[] memory t) {
        t = new address[](1);
        t[0] = a;
    }

    function _none() private pure returns (address[] memory) {
        return new address[](0);
    }

    function _send(address to, uint256 amt) private {
        (bool ok,) = to.call{value: amt}("");
        require(ok, "send");
    }

    // ---- addresses ----

    function testAddressMatchesPredictionAndIgnoresDestination() public {
        bytes32 salt = keccak256("alice/0");
        address predicted = factory.predict(salt);
        assertTrue(predicted.code.length == 0, "not deployed yet");
        assertEq(factory.deployAndFlush(salt, _none()), predicted, "deployed != predicted");
        assertTrue(predicted.code.length > 0, "deployed");
        assertEq(Forwarder(payable(predicted)).factory(), address(factory), "factory");
        vm.prank(ADMIN);
        factory.setDestination(DEST2);
        assertEq(factory.predict(salt), predicted, "setDestination does not move addresses");
    }

    // ---- receiving ----

    function testEthBeforeDeploymentIsSweptAndForwarderKeepsEth() public {
        bytes32 salt = keccak256("bob/7");
        address predicted = factory.predict(salt);
        vm.deal(address(this), 10 ether);
        _send(predicted, 3 ether);
        factory.deployAndFlush(salt, _none());
        assertEq(DEST.balance, 3 ether, "swept");
        assertEq(predicted.balance, 0, "forwarder empty");
    }

    function testEthAfterDeploymentStaysUntilSwept() public {
        bytes32 salt = keccak256("carol/1");
        address f = factory.deployAndFlush(salt, _none());
        vm.deal(address(this), 5 ether);
        _send(f, 2 ether);
        assertEq(f.balance, 2 ether, "receive() forwards nothing");
        assertEq(DEST.balance, 0, "nothing forwarded on receipt");
        factory.deployAndFlush(salt, _none());
        assertEq(DEST.balance, 2 ether, "swept");
    }

    function testTransferWith2300GasSucceedsAfterDeployment() public {
        address f = factory.deployAndFlush(keccak256("t/1"), _none());
        TransferSender s = new TransferSender();
        vm.deal(address(this), 1 ether);
        s.pay{value: 1 ether}(payable(f)); // Solidity transfer(): 2300 gas to the receiver
        assertEq(f.balance, 1 ether, "arrived");
    }

    function testMinimumGasForwardedToReceive() public {
        address f = factory.deployAndFlush(keccak256("min/1"), _none());
        vm.deal(address(this), 1 ether);
        uint256 lo = 0;
        uint256 hi = 30_000;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            (bool ok,) = f.call{value: 1, gas: mid}("");
            if (ok) hi = mid;
            else lo = mid + 1;
        }
        emit log_named_uint("min gas forwarded to receive() (value call adds the 2300 stipend)", lo);
    }

    // ---- sweeping ----

    function testRepeatedDepositSweepCycles() public {
        bytes32 salt = keccak256("cycle");
        address f = factory.predict(salt);
        vm.deal(address(this), 100 ether);
        uint256 eth;
        uint256 tok;
        for (uint256 round = 1; round <= 5; round++) {
            _send(f, round * 1 ether);
            usdt.mint(f, round * 1000);
            eth += round * 1 ether;
            tok += round * 1000;
            factory.deployAndFlush(salt, _one(address(usdt)));
            assertEq(DEST.balance, eth, "ETH at destination");
            assertEq(usdt.balanceOf(DEST), tok, "tokens at destination");
            assertEq(f.balance, 0, "forwarder ETH empty");
            assertEq(usdt.balanceOf(f), 0, "forwarder tokens empty");
            assertTrue(f.code.length > 0, "forwarder stays");
        }
    }

    function testUsdtStyleAndBoolTokensSwept() public {
        BoolToken bt = new BoolToken();
        bytes32 salt = keccak256("dave/2");
        address predicted = factory.predict(salt);
        usdt.mint(predicted, 1_000_000);
        bt.mint(predicted, 42);
        address[] memory two = new address[](2);
        two[0] = address(usdt);
        two[1] = address(bt);
        factory.deployAndFlush(salt, two);
        assertEq(usdt.balanceOf(DEST), 1_000_000, "usdt at destination");
        assertEq(bt.balanceOf(DEST), 42, "bool token at destination");
    }

    function testFalseReturningAndNonContractTokensRevert() public {
        FalseToken t = new FalseToken();
        bytes32 salt = keccak256("frank/4");
        t.mint(factory.predict(salt), 1);
        vm.expectRevert();
        factory.deployAndFlush(salt, _one(address(t)));
        vm.expectRevert();
        factory.deployAndFlush(keccak256("g"), _one(address(0x1234)));
    }

    function testReentrantTokenCannotRedirectOrStrandFunds() public {
        ReentrantToken rt = new ReentrantToken();
        bytes32 salt = keccak256("re");
        address f = factory.deployAndFlush(salt, _none());
        rt.mint(f, 500);
        try factory.deployAndFlush(salt, _one(address(rt))) {} catch {}
        // Either everything moved to the destination or nothing moved; never elsewhere.
        assertEq(rt.balanceOf(DEST) + rt.balanceOf(f), 500, "no tokens lost or diverted");
        assertEq(rt.balanceOf(ATTACKER), 0, "attacker got nothing");
    }

    function testAnyoneCanFlushButFundsOnlyReachDestination() public {
        bytes32 salt = keccak256("ivan/8");
        address f = factory.deployAndFlush(salt, _none());
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

    function testFlushZeroBalanceIsNoop() public {
        address f = factory.deployAndFlush(keccak256("kim/10"), _none());
        Forwarder(payable(f)).flushTokens(address(usdt));
        Forwarder(payable(f)).flushETH();
    }

    function testDeployAndFlushManyAndRepeatedSalt() public {
        vm.deal(address(this), 20 ether);
        bytes32[] memory salts = new bytes32[](4);
        for (uint256 i = 0; i < 3; i++) {
            salts[i] = keccak256(abi.encode("many", i));
            _send(factory.predict(salts[i]), 1 ether);
            usdt.mint(factory.predict(salts[i]), 10);
        }
        salts[3] = salts[0]; // a repeated salt just flushes again
        factory.deployAndFlushMany(salts, _one(address(usdt)));
        assertEq(DEST.balance, 3 ether, "all ETH");
        assertEq(usdt.balanceOf(DEST), 30, "all tokens");
    }

    // ---- destination, freeze, admin ----

    function testSetDestinationAdminOnlyAndOldAddressesFollow() public {
        bytes32 salt = keccak256("mv");
        address f = factory.predict(salt);
        vm.deal(address(this), 5 ether);
        _send(f, 1 ether);
        vm.prank(ATTACKER);
        vm.expectRevert();
        factory.setDestination(ATTACKER);
        assertEq(factory.destination(), DEST, "unchanged");
        vm.prank(ADMIN);
        factory.setDestination(DEST2);
        assertEq(factory.predict(salt), f, "address unchanged");
        factory.deployAndFlush(salt, _none());
        assertEq(DEST2.balance, 1 ether, "old address pays the new destination");
        assertEq(DEST.balance, 0, "old destination gets nothing");
    }

    function testFrozenRevertsAndFundsStayThenUnfreezeSweeps() public {
        bytes32 salt = keccak256("frozen");
        address f = factory.deployAndFlush(salt, _none()); // deployed
        bytes32 fresh = keccak256("frozen-fresh"); // not deployed
        vm.deal(address(this), 5 ether);
        _send(f, 1 ether);
        _send(factory.predict(fresh), 1 ether);
        usdt.mint(f, 9);

        vm.prank(ADMIN);
        factory.setDestination(address(0)); // freeze
        vm.expectRevert();
        factory.deployAndFlush(salt, _one(address(usdt)));
        vm.expectRevert();
        factory.deployAndFlush(fresh, _none());
        vm.expectRevert();
        Forwarder(payable(f)).flushETH();
        vm.expectRevert();
        Forwarder(payable(f)).flushTokens(address(usdt));
        assertEq(f.balance, 1 ether, "ETH stays");
        assertEq(usdt.balanceOf(f), 9, "tokens stay");
        assertEq(factory.predict(fresh).code.length, 0, "frozen deploys nothing");
        assertEq(factory.predict(fresh).balance, 1 ether, "undeployed address keeps its ETH");

        vm.prank(ADMIN);
        factory.setDestination(DEST);
        factory.deployAndFlush(salt, _one(address(usdt)));
        factory.deployAndFlush(fresh, _none());
        assertEq(DEST.balance, 2 ether, "ETH swept after unfreeze");
        assertEq(usdt.balanceOf(DEST), 9, "tokens swept after unfreeze");
    }

    function testTwoStepAdminTransfer() public {
        vm.prank(ATTACKER);
        vm.expectRevert();
        factory.transferAdmin(ATTACKER);

        vm.prank(ADMIN);
        factory.transferAdmin(ADMIN2);
        assertEq(factory.admin(), ADMIN, "still the old admin");
        // Nominated but not yet accepted: no power.
        vm.prank(ADMIN2);
        vm.expectRevert();
        factory.setDestination(ADMIN2);
        // A non-pending caller cannot accept.
        vm.prank(ATTACKER);
        vm.expectRevert();
        factory.acceptAdmin();

        vm.prank(ADMIN2);
        factory.acceptAdmin();
        assertEq(factory.admin(), ADMIN2, "new admin");
        assertEq(factory.pendingAdmin(), address(0), "pending cleared");
        // The old admin lost power.
        vm.prank(ADMIN);
        vm.expectRevert();
        factory.setDestination(ADMIN);
        vm.prank(ADMIN);
        vm.expectRevert();
        factory.transferAdmin(ADMIN);
        vm.prank(ADMIN2);
        factory.setDestination(DEST2);
        assertEq(factory.destination(), DEST2, "new admin works");
    }

    // ---- guardian, frozen by default ----

    function testGuardianFreezesButCannotDoAnythingElse() public {
        bytes32 salt = keccak256("g1");
        address f = factory.deployAndFlush(salt, _none());
        vm.deal(address(this), 3 ether);
        _send(f, 1 ether);

        vm.prank(ATTACKER);
        vm.expectRevert();
        factory.freeze();
        assertEq(factory.destination(), DEST, "non-guardian could not freeze");

        vm.prank(GUARDIAN);
        factory.freeze();
        assertEq(factory.destination(), address(0), "guardian froze");
        vm.expectRevert();
        factory.deployAndFlush(salt, _none());
        assertEq(f.balance, 1 ether, "funds stay in the deposit address");

        vm.prank(GUARDIAN);
        factory.freeze(); // already frozen: no-op
        assertEq(factory.destination(), address(0), "still frozen");

        // Guardian can do nothing else.
        vm.prank(GUARDIAN);
        vm.expectRevert();
        factory.setDestination(DEST);
        vm.prank(GUARDIAN);
        vm.expectRevert();
        factory.transferAdmin(GUARDIAN);
        vm.prank(GUARDIAN);
        vm.expectRevert();
        factory.setGuardian(GUARDIAN2);
        assertEq(factory.destination(), address(0), "guardian cannot unfreeze");
        assertEq(factory.admin(), ADMIN, "admin untouched");

        vm.prank(ADMIN);
        factory.setDestination(DEST);
        factory.deployAndFlush(salt, _none());
        assertEq(DEST.balance, 1 ether, "admin unfroze and sweep worked");
    }

    function testAdminCanFreezeAndRotateGuardian() public {
        vm.prank(ADMIN);
        factory.freeze();
        assertEq(factory.destination(), address(0), "admin froze");

        vm.prank(ATTACKER);
        vm.expectRevert();
        factory.setGuardian(ATTACKER);
        vm.prank(ADMIN);
        vm.expectRevert();
        factory.setGuardian(address(0));
        vm.prank(ADMIN);
        factory.setGuardian(GUARDIAN2);

        vm.prank(ADMIN);
        factory.setDestination(DEST);
        vm.prank(GUARDIAN); // the old guardian lost its power
        vm.expectRevert();
        factory.freeze();
        assertEq(factory.destination(), DEST, "old guardian could not freeze");
        vm.prank(GUARDIAN2);
        factory.freeze();
        assertEq(factory.destination(), address(0), "new guardian can");
    }

    function testZeroAdminOrGuardianRevertsAtDeployment() public {
        vm.expectRevert();
        new ForwarderFactory(DEST, address(0), GUARDIAN);
        vm.expectRevert();
        new ForwarderFactory(DEST, ADMIN, address(0));
    }

    function testDeployedFrozenDepositsArriveThenAdminStartsSweeping() public {
        ForwarderFactory fz = new ForwarderFactory(address(0), ADMIN, GUARDIAN);
        bytes32 salt = keccak256("frozen-start");
        address a = fz.predict(salt);
        vm.deal(address(this), 3 ether);
        usdt.mint(a, 6);
        _send(a, 1 ether); // before deployment, while frozen
        assertEq(a.balance, 1 ether, "deposit arrived");
        vm.expectRevert();
        fz.deployAndFlush(salt, _one(address(usdt)));
        assertEq(a.balance, 1 ether, "funds stay");
        assertEq(a.code.length, 0, "nothing deployed while frozen");

        vm.prank(ADMIN);
        fz.setDestination(DEST);
        fz.deployAndFlush(salt, _one(address(usdt)));
        assertEq(DEST.balance, 1 ether, "swept");
        assertEq(usdt.balanceOf(DEST), 6, "tokens swept");
    }

    // ---- Swept event ----

    bytes32 constant SWEPT = keccak256("Swept(address,uint256)");

    function _swept(Vm.Log[] memory logs, address emitter) private pure returns (address[] memory tok, uint256[] memory amt, uint256 n) {
        tok = new address[](logs.length);
        amt = new uint256[](logs.length);
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == emitter && logs[i].topics[0] == SWEPT) {
                tok[n] = address(uint160(uint256(logs[i].topics[1])));
                amt[n] = abi.decode(logs[i].data, (uint256));
                n++;
            }
        }
    }

    function testSweptEventReportsWhatMovedAndNothingWhenEmpty() public {
        bytes32 salt = keccak256("eve/3");
        address predicted = factory.predict(salt);
        usdt.mint(predicted, 777);
        vm.deal(address(this), 10 ether);
        _send(predicted, 3 ether);
        vm.recordLogs();
        factory.deployAndFlush(salt, _one(address(usdt)));
        (address[] memory tok, uint256[] memory amt, uint256 n) = _swept(vm.getRecordedLogs(), predicted);
        assertEq(n, 2, "two Swept events: ETH and the token");
        assertEq(tok[0], address(0), "ETH first, token zero");
        assertEq(amt[0], 3 ether, "ETH amount");
        assertEq(tok[1], address(usdt), "token second");
        assertEq(amt[1], 777, "token amount");

        // A second flush with nothing left emits nothing.
        vm.recordLogs();
        factory.deployAndFlush(salt, _one(address(usdt)));
        (,, n) = _swept(vm.getRecordedLogs(), predicted);
        assertEq(n, 0, "nothing moved, no event");
    }

    function testSweptEventOnDirectFlushAndOnlyTokenWhenNoEth() public {
        bytes32 salt = keccak256("fay/4");
        address predicted = factory.predict(salt);
        factory.deployAndFlush(salt, _none());
        usdt.mint(predicted, 9);
        vm.recordLogs();
        Forwarder(payable(predicted)).flushTokens(address(usdt));
        (address[] memory tok, uint256[] memory amt, uint256 n) = _swept(vm.getRecordedLogs(), predicted);
        assertEq(n, 1, "one event");
        assertEq(tok[0], address(usdt), "token");
        assertEq(amt[0], 9, "amount");
    }

    // ---- gas ----

    function testGas() public {
        bytes32 salt = keccak256("mia/12");
        address predicted = factory.predict(salt);
        usdt.mint(predicted, 5);
        vm.deal(address(this), 100 ether);
        _send(predicted, 1 ether);
        address[] memory toks = _one(address(usdt));
        uint256 g = gasleft();
        factory.deployAndFlush(salt, toks);
        emit log_named_uint("gas deployAndFlush first (deploy + ETH + 1 token)", g - gasleft());

        usdt.mint(predicted, 5);
        _send(predicted, 1 ether);
        g = gasleft();
        factory.deployAndFlush(salt, toks);
        emit log_named_uint("gas deployAndFlush repeat (ETH + 1 token)", g - gasleft());

        usdt.mint(predicted, 5);
        g = gasleft();
        Forwarder(payable(predicted)).flushTokens(address(usdt));
        emit log_named_uint("gas flushTokens direct (1 token)", g - gasleft());

        _send(predicted, 1 ether);
        g = gasleft();
        Forwarder(payable(predicted)).flushETH();
        emit log_named_uint("gas flushETH direct", g - gasleft());

        bytes32[] memory salts = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            salts[i] = keccak256(abi.encode("b", i));
            _send(factory.predict(salts[i]), 1 ether);
            usdt.mint(factory.predict(salts[i]), 5);
        }
        g = gasleft();
        factory.deployAndFlushMany(salts, toks);
        emit log_named_uint("gas deployAndFlushMany 10 first (ETH + 1 token each)", g - gasleft());
        for (uint256 i = 0; i < 10; i++) {
            _send(factory.predict(salts[i]), 1 ether);
            usdt.mint(factory.predict(salts[i]), 5);
        }
        g = gasleft();
        factory.deployAndFlushMany(salts, toks);
        emit log_named_uint("gas deployAndFlushMany 10 repeat (ETH + 1 token each)", g - gasleft());
    }
}
