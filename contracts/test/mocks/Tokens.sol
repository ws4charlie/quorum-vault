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
