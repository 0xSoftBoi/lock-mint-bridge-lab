// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title SourceVault
/// @notice The source-chain half of a lock-and-mint bridge: it custodies collateral and
/// is the authority for `totalLocked`, the right-hand side of the bridge's one big
/// invariant — `wrapped supply on destination <= collateral locked here`.
///
/// Every value-moving exit (unlock-after-burn, or refund) passes through the attestation
/// gate, and each `commitId` can reach at most ONE terminal outcome {UNLOCKED, REFUNDED}.
/// That on-chain XOR is what closes the cross-domain "minted AND refunded" double-spend:
/// the refund path can no longer fire in ignorance of the mint/unlock path.
contract SourceVault {
    enum Status {
        NONE,
        LOCKED,
        UNLOCKED,
        REFUNDED
    }

    struct Commit {
        address from;
        uint256 amount;
        Status status;
    }

    // Domain tags keep an unlock signature from being replayed as a refund signature.
    bytes32 public constant UNLOCK_DOMAIN = keccak256("LOCKMINT_UNLOCK_V1");
    bytes32 public constant REFUND_DOMAIN = keccak256("LOCKMINT_REFUND_V1");

    IERC20 public immutable asset;
    IAttestationVerifier public verifier;
    address public owner;

    /// Set false ONLY to demonstrate the bug (see the mutation test): with the gate off,
    /// a forged exit drains collateral and the supply<=collateral invariant breaks.
    bool public attestationRequired = true;

    uint256 public totalLocked;
    uint256 public nextNonce;
    mapping(bytes32 => Commit) public commits;

    error NotOwner();
    error BadStatus();
    error Unauthorized();

    event Locked(
        bytes32 indexed commitId, address indexed from, address recipient, uint256 amount, uint256 destChainId
    );
    event Unlocked(bytes32 indexed commitId, address indexed to, uint256 amount);
    event Refunded(bytes32 indexed commitId, address indexed to, uint256 amount);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(IERC20 asset_, IAttestationVerifier verifier_, address owner_) {
        asset = asset_;
        verifier = verifier_;
        owner = owner_;
    }

    function setVerifier(IAttestationVerifier v) external onlyOwner {
        verifier = v;
    }

    function setAttestationRequired(bool required) external onlyOwner {
        attestationRequired = required;
    }

    /// Lock collateral and open a commit. `commitId` is derived from this chain + this
    /// contract + a local nonce, so it is unique and not attacker-chosen.
    function lock(uint256 amount, uint256 destChainId, address recipient) external returns (bytes32 commitId) {
        commitId = keccak256(abi.encode(block.chainid, address(this), nextNonce++));
        commits[commitId] = Commit({from: msg.sender, amount: amount, status: Status.LOCKED});
        totalLocked += amount;
        require(asset.transferFrom(msg.sender, address(this), amount), "transferFrom");
        emit Locked(commitId, msg.sender, recipient, amount, destChainId);
    }

    /// Release collateral after the wrapped tokens were burned on the destination.
    /// Gated: an operator attests that the burn happened, binding every parameter.
    function unlock(bytes32 commitId, address to, uint256 sourceChainId, bytes calldata attestation) external {
        Commit storage c = commits[commitId];
        if (c.status != Status.LOCKED) revert BadStatus();
        _gate(UNLOCK_DOMAIN, commitId, to, c.amount, sourceChainId, attestation);
        c.status = Status.UNLOCKED;
        totalLocked -= c.amount;
        require(asset.transfer(to, c.amount), "transfer");
        emit Unlocked(commitId, to, c.amount);
    }

    /// Refund the original depositor if the transfer never completed on the destination.
    /// Same gate; mutually exclusive with unlock by the LOCKED-status check.
    function refund(bytes32 commitId, uint256 sourceChainId, bytes calldata attestation) external {
        Commit storage c = commits[commitId];
        if (c.status != Status.LOCKED) revert BadStatus();
        _gate(REFUND_DOMAIN, commitId, c.from, c.amount, sourceChainId, attestation);
        c.status = Status.REFUNDED;
        totalLocked -= c.amount;
        require(asset.transfer(c.from, c.amount), "transfer");
        emit Refunded(commitId, c.from, c.amount);
    }

    function digest(bytes32 domain, bytes32 commitId, address recipient, uint256 amount, uint256 sourceChainId)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(domain, block.chainid, address(this), commitId, recipient, amount, sourceChainId));
    }

    function _gate(
        bytes32 domain,
        bytes32 commitId,
        address recipient,
        uint256 amount,
        uint256 sourceChainId,
        bytes calldata attestation
    ) internal view {
        if (!attestationRequired) return; // mutation switch — see test
        if (!verifier.verify(digest(domain, commitId, recipient, amount, sourceChainId), attestation)) {
            revert Unauthorized();
        }
    }
}
