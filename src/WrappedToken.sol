// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WrappedToken
/// @notice The destination-chain representation of the locked asset. Minimal ERC-20.
/// @dev Embeds one audit lesson directly: the token *admin* must not be a parallel,
/// unconstrained minter. `admin` can only rotate which contract holds the `minter`
/// role; it cannot mint, and `admin != minter` is enforced — otherwise an admin key
/// is a second, silent path to inflate supply past the locked collateral, defeating
/// the whole supply<=collateral invariant.
contract WrappedToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public admin; // rotates the minter; CANNOT mint
    address public minter; // the MintAdapter; the ONLY minter/burner

    error NotMinter();
    error NotAdmin();
    error AdminCannotBeMinter();
    error ZeroAddress();

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event MinterUpdated(address indexed minter);

    constructor(string memory name_, string memory symbol_, address admin_, address minter_) {
        if (admin_ == address(0) || minter_ == address(0)) revert ZeroAddress();
        if (admin_ == minter_) revert AdminCannotBeMinter();
        name = name_;
        symbol = symbol_;
        admin = admin_;
        minter = minter_;
    }

    function setMinter(address newMinter) external {
        if (msg.sender != admin) revert NotAdmin();
        if (newMinter == address(0)) revert ZeroAddress();
        if (newMinter == admin) revert AdminCannotBeMinter();
        minter = newMinter;
        emit MinterUpdated(newMinter);
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != minter) revert NotMinter();
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function burn(address from, uint256 amount) external {
        if (msg.sender != minter) revert NotMinter();
        balanceOf[from] -= amount; // reverts on underflow (0.8)
        totalSupply -= amount;
        emit Transfer(from, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
