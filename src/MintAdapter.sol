// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationVerifier} from "./IAttestationVerifier.sol";
import {WrappedToken} from "./WrappedToken.sol";

/// @title MintAdapter
/// @notice The destination-chain half: it mints the wrapped token against an operator
/// attestation that a lock happened on the source chain, and burns it to start the
/// return trip. It is the left-hand side of `wrapped supply <= collateral locked`.
///
/// The whole security of the mint reduces to one line — `verifier.verify(digest, att)` —
/// over a digest that binds the domain, THIS chain id, THIS contract, the commitId,
/// recipient, amount, and source chain id. Drop any field and you reopen a replay:
/// without `address(this)` a signature is replayable across deployments; without
/// `block.chainid` it crosses chains; without `commitId` it mints twice.
contract MintAdapter {
    bytes32 public constant MINT_DOMAIN = keccak256("LOCKMINT_MINT_V1");

    WrappedToken public immutable token;
    IAttestationVerifier public verifier;
    address public owner;

    /// Mutation switch — see the test. With the gate off, a forged attestation mints
    /// unbacked supply and breaks the supply<=collateral invariant in one call.
    bool public attestationRequired = true;

    uint256 public nextReleaseNonce;
    mapping(bytes32 => bool) public minted; // replay guard, keyed by commitId

    error NotOwner();
    error AlreadyMinted();
    error Unauthorized();

    event Minted(bytes32 indexed commitId, address indexed recipient, uint256 amount, uint256 sourceChainId);
    event BurnForRelease(
        bytes32 indexed releaseId, address indexed from, address recipient, uint256 amount, uint256 destChainId
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(WrappedToken token_, IAttestationVerifier verifier_, address owner_) {
        token = token_;
        verifier = verifier_;
        owner = owner_;
    }

    function setVerifier(IAttestationVerifier v) external onlyOwner {
        verifier = v;
    }

    function setAttestationRequired(bool required) external onlyOwner {
        attestationRequired = required;
    }

    function mint(
        bytes32 commitId,
        address recipient,
        uint256 amount,
        uint256 sourceChainId,
        bytes calldata attestation
    ) external {
        if (minted[commitId]) revert AlreadyMinted();
        if (attestationRequired) {
            bytes32 d = digest(commitId, recipient, amount, sourceChainId);
            if (!verifier.verify(d, attestation)) revert Unauthorized();
        }
        minted[commitId] = true;
        token.mint(recipient, amount);
        emit Minted(commitId, recipient, amount, sourceChainId);
    }

    /// Burn wrapped tokens to start the return leg; the relayer carries the
    /// `BurnForRelease` event to the source vault's `unlock`.
    function burn(uint256 amount, uint256 destChainId, address recipient) external returns (bytes32 releaseId) {
        releaseId = keccak256(abi.encode(block.chainid, address(this), nextReleaseNonce++));
        token.burn(msg.sender, amount);
        emit BurnForRelease(releaseId, msg.sender, recipient, amount, destChainId);
    }

    function digest(bytes32 commitId, address recipient, uint256 amount, uint256 sourceChainId)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(MINT_DOMAIN, block.chainid, address(this), commitId, recipient, amount, sourceChainId)
        );
    }
}
