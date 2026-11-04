// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice SPIKE (not wired into the Go adapter). One-shot sweeper: a deposit
/// address is the CREATE2 address of a contract whose whole logic runs in its
/// constructor and ends with SELFDESTRUCT. Since EIP-6780 (Cancun) SELFDESTRUCT
/// removes an account only when it runs in the transaction that created it,
/// which is exactly this case, so no code stays on the address between sweeps.
///
/// - The address depends on (factory, salt) only: OneShot's init code has no
///   constructor arguments, so changing `destination` never moves an address.
/// - Anyone may sweep; funds can only reach `destination`. Only `admin` (meant to
///   be a cold-key address) can change `destination`.
contract SweepFactory {
    address payable public destination;
    address public immutable admin;

    // Transient storage (cleared at the end of every transaction).
    bytes32 private constant LOCK = keccak256("qv.sweep.lock");
    bytes32 private constant LEN = keccak256("qv.sweep.len");
    bytes32 private constant BASE = keccak256("qv.sweep.tokens");

    event DestinationChanged(address indexed previous, address indexed current);

    error NotAdmin();
    error ZeroAddress();
    error Reentered();
    error DuplicateSalt();

    constructor(address payable destination_, address admin_) {
        if (destination_ == address(0) || admin_ == address(0)) revert ZeroAddress();
        destination = destination_;
        admin = admin_;
        emit DestinationChanged(address(0), destination_);
    }

    function setDestination(address payable newDestination) external {
        if (msg.sender != admin) revert NotAdmin();
        if (newDestination == address(0)) revert ZeroAddress();
        emit DestinationChanged(destination, newDestination);
        destination = newDestination;
    }

    /// @notice Address of the one-shot for `salt`. Independent of `destination`.
    function predict(bytes32 salt) public view returns (address) {
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(type(OneShot).creationCode)));
        return address(uint160(uint256(h)));
    }

    /// @notice Sweeps ETH and each listed token from the deposit address of `salt`
    /// to `destination`. All or nothing: a failing token transfer reverts everything.
    function sweep(bytes32 salt, address[] calldata tokens) external {
        _begin(tokens);
        _deploy(salt);
        _end();
    }

    /// @notice Same for many addresses with one token list. A salt listed twice
    /// reverts the whole call (the first one-shot is still alive until the end of the
    /// transaction, so the second CREATE2 collides).
    function sweepMany(bytes32[] calldata salts, address[] calldata tokens) external {
        _begin(tokens);
        for (uint256 i = 0; i < salts.length; i++) {
            _deploy(salts[i]);
        }
        _end();
    }

    /// @dev Read by OneShot's constructor (msg.sender is this factory).
    function context() external view returns (address payable dest, address[] memory tokens) {
        dest = destination;
        bytes32 lenSlot = LEN;
        bytes32 base = BASE;
        uint256 n;
        assembly {
            n := tload(lenSlot)
        }
        tokens = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            address t;
            assembly {
                t := tload(add(base, i))
            }
            tokens[i] = t;
        }
    }

    function _begin(address[] calldata tokens) private {
        bytes32 lock = LOCK;
        bytes32 lenSlot = LEN;
        bytes32 base = BASE;
        uint256 locked;
        assembly {
            locked := tload(lock)
        }
        if (locked != 0) revert Reentered();
        uint256 n = tokens.length;
        assembly {
            tstore(lock, 1)
            tstore(lenSlot, n)
        }
        for (uint256 i = 0; i < n; i++) {
            address t = tokens[i];
            assembly {
                tstore(add(base, i), t)
            }
        }
    }

    function _deploy(bytes32 salt) private {
        // The one-shot of a salt swept earlier in this transaction is still alive until
        // the transaction ends, so a second CREATE2 would collide and burn all forwarded
        // gas. Refuse early and cheaply instead.
        bytes32 seen = keccak256(abi.encode(BASE, salt));
        uint256 already;
        assembly {
            already := tload(seen)
            tstore(seen, 1)
        }
        if (already != 0) revert DuplicateSalt();
        new OneShot{salt: salt}();
    }

    function _end() private {
        bytes32 lock = LOCK;
        bytes32 lenSlot = LEN;
        assembly {
            tstore(lock, 0)
            tstore(lenSlot, 0)
        }
    }
}

interface ISweepContext {
    function context() external view returns (address payable dest, address[] memory tokens);
}

/// @dev All logic is in the constructor. It reads destination and token list from
/// its deployer, moves each token's whole balance (USDT-safe), and self-destructs,
/// sending the ETH balance to destination. Nothing stays on the address.
contract OneShot {
    error TransferFailed();

    constructor() {
        (address payable dest, address[] memory tokens) = ISweepContext(msg.sender).context();
        for (uint256 i = 0; i < tokens.length; i++) {
            _move(tokens[i], dest);
        }
        selfdestruct(dest);
    }

    function _move(address token, address dest) private {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, address(this)));
        if (!ok || ret.length < 32) revert TransferFailed();
        uint256 bal = abi.decode(ret, (uint256));
        if (bal == 0) return;
        (ok, ret) = token.call(abi.encodeWithSelector(0xa9059cbb, dest, bal));
        if (!ok) revert TransferFailed();
        if (ret.length != 0 && (ret.length != 32 || abi.decode(ret, (uint256)) != 1)) revert TransferFailed();
    }
}
