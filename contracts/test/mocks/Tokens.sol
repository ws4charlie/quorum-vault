// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @dev USDT-style: transfer returns nothing.
contract UsdtLike {
    event Transfer(address indexed from, address indexed to, uint256 value);
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }

    function transfer(address to, uint256 amt) external {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        emit Transfer(msg.sender, to, amt);
    }
}

/// @dev Standard ERC-20 behaviour: transfer returns true.
contract BoolToken {
    event Transfer(address indexed from, address indexed to, uint256 value);
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        emit Transfer(msg.sender, to, amt);
        return true;
    }
}

/// @dev Broken token: transfer returns false without moving anything.
contract FalseToken {
    event Transfer(address indexed from, address indexed to, uint256 value);
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/// @dev Sends ETH with Solidity transfer() (2,300 gas to the receiver).
contract TransferSender {
    function pay(address payable to) external payable {
        to.transfer(msg.value);
    }
}

/// @dev Re-enters the forwarder's flushTokens from inside transfer().
contract ReentrantToken {
    mapping(address => uint256) public balanceOf;
    bool private entered;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        if (!entered) {
            entered = true;
            (bool ok,) = msg.sender.call(abi.encodeWithSignature("flushTokens(address)", address(this)));
            ok;
        }
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        emit Transfer(msg.sender, to, amt);
        return true;
    }
}

/// @dev A minimal stand-in for Circle's USDC (FiatTokenV2) on a local devnet: ERC-20 plus EIP-3009 `transferWithAuthorization`, written to behave as
/// USDC does (internal/chain/evm/eip3009.go, docs/evm.md): the same EIP-712 domain fields (name, version, chainId, verifyingContract), the same
/// TransferWithAuthorization type, a caller that need not be the payer, the validity window checked against block.timestamp with both bounds exclusive,
/// a 32-byte nonce used once per authorizer (`authorizationState`), the `AuthorizationUsed` event, and an ECRecover that refuses a high-s signature and a
/// v other than 27 or 28 (OpenZeppelin-style, as Circle's). It is a test token only: it has no blocklist, pause or minter roles.
contract Eip3009Token {
    string public name;
    string public constant version = "2";
    uint8 public constant decimals = 6;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 private constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    constructor(string memory name_) {
        name = name_;
    }

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this)));
    }

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        emit Transfer(msg.sender, to, amt);
        return true;
    }

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp > validAfter, "FiatTokenV2: authorization is not yet valid");
        require(block.timestamp < validBefore, "FiatTokenV2: authorization is expired");
        require(!authorizationState[from][nonce], "FiatTokenV2: authorization is used or canceled");
        bytes32 structHash = keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), structHash));
        require(_recover(digest, v, r, s) == from, "FiatTokenV2: invalid signature");
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }

    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) private pure returns (address) {
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "ECRecover: invalid signature 's' value");
        require(v == 27 || v == 28, "ECRecover: invalid signature 'v' value");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "ECRecover: invalid signature");
        return signer;
    }
}
