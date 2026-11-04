// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// Run with `forge test --isolate`: each top-level call is its own transaction, so
// the EIP-6780 behavior of SELFDESTRUCT is real (inside one transaction it would
// look different).

import {Base} from "./Base.sol";
import {SweepFactory} from "../src/SweepFactory.sol";
import {ForwarderFactory} from "../src/ForwarderFactory.sol";
import {UsdtLike, BoolToken, FalseToken} from "./mocks/Tokens.sol";

contract ReentrantToken {
    SweepFactory public f;
    bytes32 public salt;

    constructor(SweepFactory f_, bytes32 salt_) {
        f = f_;
        salt = salt_;
    }

    function balanceOf(address) external pure returns (uint256) {
        return 1;
    }

    function transfer(address, uint256) external returns (bool) {
        f.sweep(salt, new address[](0)); // re-enter while a sweep is running
        return true;
    }
}

contract SweepFactoryTest is Base {
    address payable constant DEST = payable(address(0xD357));
    address payable constant DEST2 = payable(address(0xD358));
    address constant ADMIN = address(0xAD41);
    address constant ATTACKER = address(0xBAD);
    SweepFactory f;
    UsdtLike usdt;

    function setUp() public {
        f = new SweepFactory(DEST, ADMIN);
        usdt = new UsdtLike();
    }

    function _toks(address a) private pure returns (address[] memory t) {
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

    function testRepeatedDepositSweepCycles() public {
        bytes32 salt = keccak256("cycle");
        address a = f.predict(salt);
        vm.deal(address(this), 100 ether);
        uint256 ethExpected;
        uint256 tokExpected;
        for (uint256 round = 1; round <= 5; round++) {
            _send(a, round * 1 ether);
            usdt.mint(a, round * 1000);
            ethExpected += round * 1 ether;
            tokExpected += round * 1000;
            f.sweep(salt, _toks(address(usdt)));
            assertEq(DEST.balance, ethExpected, "ETH at destination");
            assertEq(usdt.balanceOf(DEST), tokExpected, "tokens at destination");
            assertEq(a.balance, 0, "address ETH empty");
            assertEq(usdt.balanceOf(a), 0, "address tokens empty");
            assertEq(a.code.length, 0, "no code left on the address");
            // A send with only the 2300 stipend (transfer()) succeeds on a code-less address.
        }
    }

    // A send that gives the receiver only the 2300-gas stipend (Solidity transfer()) works
    // on a swept address, because no code is left.
    //
    // Foundry quirk, not chain behavior: under --isolate, a second sweep of an address that an
    // earlier isolated transaction already self-destructed did not credit ETH that was on the
    // address before the CREATE2 (balance went to 0, destination unchanged), so this test does
    // not sweep again. The same sequence runs on real anvil nodes (Cancun and the latest
    // hardfork) in internal/chain/evm/sweep_spike_test.go and moves every wei.
    function testStipendSendAfterSweep() public {
        bytes32 salt = keccak256("stipend");
        address a = f.predict(salt);
        vm.deal(address(this), 10 ether);
        _send(a, 1 ether);
        f.sweep(salt, _none());
        assertEq(DEST.balance, 1 ether, "swept");
        assertEq(a.code.length, 0, "no code");
        (bool ok,) = a.call{value: 1, gas: 0}("");
        assertTrue(ok, "stipend send to a swept address succeeds");
        assertEq(a.balance, 1, "arrived");
        assertEq(a.code.length, 0, "still no code");
    }

    function testEthOnlyTokenOnlyBothAndEmpty() public {
        vm.deal(address(this), 10 ether);
        bytes32 s1 = keccak256("eth-only");
        _send(f.predict(s1), 2 ether);
        f.sweep(s1, _toks(address(usdt))); // token listed, none held
        assertEq(DEST.balance, 2 ether, "eth only");

        bytes32 s2 = keccak256("tok-only");
        usdt.mint(f.predict(s2), 55);
        f.sweep(s2, _toks(address(usdt)));
        assertEq(usdt.balanceOf(DEST), 55, "token only");

        BoolToken bt = new BoolToken();
        bytes32 s3 = keccak256("both");
        _send(f.predict(s3), 1 ether);
        usdt.mint(f.predict(s3), 7);
        bt.mint(f.predict(s3), 9);
        address[] memory two = new address[](2);
        two[0] = address(usdt);
        two[1] = address(bt);
        f.sweep(s3, two);
        assertEq(DEST.balance, 3 ether, "both: eth");
        assertEq(usdt.balanceOf(DEST), 62, "both: usdt-style");
        assertEq(bt.balanceOf(DEST), 9, "both: bool token");

        f.sweep(keccak256("empty"), _none()); // nothing there: succeeds
        assertEq(f.predict(keccak256("empty")).code.length, 0, "empty sweep leaves no code");
    }

    function testSetDestinationAdminOnlyAndAddressesDoNotMove() public {
        bytes32 salt = keccak256("mv");
        address before_ = f.predict(salt);
        vm.deal(address(this), 5 ether);
        vm.prank(ATTACKER);
        vm.expectRevert();
        f.setDestination(payable(ATTACKER));
        assertEq(f.destination(), DEST, "unchanged by attacker");

        _send(before_, 1 ether); // deposited under the old destination
        vm.prank(ADMIN);
        f.setDestination(DEST2);
        assertEq(f.predict(salt), before_, "address unchanged by setDestination");
        f.sweep(salt, _none());
        assertEq(DEST2.balance, 1 ether, "existing deposit goes to the new destination");
        assertEq(DEST.balance, 0, "old destination gets nothing");
    }

    function testSameSaltTwiceInOneTransactionRevertsAtomically() public {
        bytes32 salt = keccak256("dup");
        address a = f.predict(salt);
        vm.deal(address(this), 3 ether);
        _send(a, 1 ether);
        usdt.mint(a, 11);
        bytes32[] memory salts = new bytes32[](2);
        salts[0] = salt;
        salts[1] = salt;
        vm.expectRevert();
        f.sweepMany(salts, _toks(address(usdt)));
        // Nothing moved, nothing stranded, no code left.
        assertEq(a.balance, 1 ether, "ETH still on the address");
        assertEq(usdt.balanceOf(a), 11, "tokens still on the address");
        assertEq(a.code.length, 0, "no code");
        f.sweep(salt, _toks(address(usdt))); // and a normal sweep still works
        assertEq(DEST.balance, 1 ether, "later sweep ok");
    }

    function testRevertingTokenRevertsEverythingAndLeavesNoCode() public {
        FalseToken bad = new FalseToken();
        bytes32 salt = keccak256("bad");
        address a = f.predict(salt);
        vm.deal(address(this), 3 ether);
        _send(a, 1 ether);
        bad.mint(a, 1);
        address[] memory two = new address[](2);
        two[0] = address(usdt);
        two[1] = address(bad);
        vm.expectRevert();
        f.sweep(salt, two);
        assertEq(a.balance, 1 ether, "ETH stays");
        assertEq(a.code.length, 0, "no code");
        f.sweep(salt, _toks(address(usdt))); // omit the bad token: ETH moves
        assertEq(DEST.balance, 1 ether, "recovered by omitting the token");
    }

    function testReentrantTokenIsBlocked() public {
        bytes32 salt = keccak256("re");
        ReentrantToken rt = new ReentrantToken(f, salt);
        vm.expectRevert();
        f.sweep(salt, _toks(address(rt)));
    }

    function testManyAddressesInOneCall() public {
        vm.deal(address(this), 20 ether);
        bytes32[] memory salts = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            salts[i] = keccak256(abi.encode("many", i));
            _send(f.predict(salts[i]), 1 ether);
            usdt.mint(f.predict(salts[i]), 100);
        }
        f.sweepMany(salts, _toks(address(usdt)));
        assertEq(DEST.balance, 10 ether, "all ETH");
        assertEq(usdt.balanceOf(DEST), 1000, "all tokens");
        for (uint256 i = 0; i < 10; i++) {
            assertEq(f.predict(salts[i]).code.length, 0, "no code");
        }
    }

    // ---- gas: A (Forwarder + ForwarderFactory) vs B (SweepFactory), ETH + 1 token ----

    function testGasComparison() public {
        vm.deal(address(this), 1000 ether);
        ForwarderFactory a = new ForwarderFactory(DEST);
        address[] memory toks = _toks(address(usdt));

        // first sweep, single address
        bytes32 sa = keccak256("g-a");
        _send(a.predict(sa), 1 ether);
        usdt.mint(a.predict(sa), 5);
        uint256 g = gasleft();
        a.deployAndFlush(sa, toks);
        emit log_named_uint("A first sweep (deploy+ETH+token)", g - gasleft());

        bytes32 sb = keccak256("g-b");
        _send(f.predict(sb), 1 ether);
        usdt.mint(f.predict(sb), 5);
        g = gasleft();
        f.sweep(sb, toks);
        emit log_named_uint("B first sweep (ETH+token)", g - gasleft());

        // repeat sweep, same address
        _send(a.predict(sa), 1 ether);
        usdt.mint(a.predict(sa), 5);
        g = gasleft();
        a.deployAndFlush(sa, toks);
        emit log_named_uint("A repeat sweep (ETH+token)", g - gasleft());

        _send(f.predict(sb), 1 ether);
        usdt.mint(f.predict(sb), 5);
        g = gasleft();
        f.sweep(sb, toks);
        emit log_named_uint("B repeat sweep (ETH+token)", g - gasleft());

        // 10 addresses (A has no batch call: ten calls, each its own transaction)
        bytes32[] memory sas = new bytes32[](10);
        bytes32[] memory sbs = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            sas[i] = keccak256(abi.encode("ga", i));
            sbs[i] = keccak256(abi.encode("gb", i));
            _send(a.predict(sas[i]), 1 ether);
            usdt.mint(a.predict(sas[i]), 5);
            _send(f.predict(sbs[i]), 1 ether);
            usdt.mint(f.predict(sbs[i]), 5);
        }
        g = gasleft();
        for (uint256 i = 0; i < 10; i++) {
            a.deployAndFlush(sas[i], toks);
        }
        emit log_named_uint("A 10 first sweeps, 10 calls (sum, excl. 21000 base each)", g - gasleft());
        g = gasleft();
        f.sweepMany(sbs, toks);
        emit log_named_uint("B 10 first sweeps, one sweepMany", g - gasleft());

        // 10 repeats
        for (uint256 i = 0; i < 10; i++) {
            _send(a.predict(sas[i]), 1 ether);
            usdt.mint(a.predict(sas[i]), 5);
            _send(f.predict(sbs[i]), 1 ether);
            usdt.mint(f.predict(sbs[i]), 5);
        }
        g = gasleft();
        for (uint256 i = 0; i < 10; i++) {
            a.deployAndFlush(sas[i], toks);
        }
        emit log_named_uint("A 10 repeat sweeps, 10 calls (sum, excl. 21000 base each)", g - gasleft());
        g = gasleft();
        f.sweepMany(sbs, toks);
        emit log_named_uint("B 10 repeat sweeps, one sweepMany", g - gasleft());
    }
}
