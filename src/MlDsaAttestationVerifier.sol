// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

/// @title MlDsaAttestationVerifier
/// @notice The post-quantum gate: an attestation is an ML-DSA-65 (Dilithium, FIPS-204)
/// signature by the authorized operator over the bridge `digest`. The lattice math is
/// not done in Solidity (it is NTT-heavy and ~megagas) — it is delegated to the
/// **EIP-8051** ML-DSA verification precompile, so this contract only does the binding,
/// authorization, and input encoding. Drop it in anywhere `IAttestationVerifier` is used
/// (vault, adapter) on a chain where the precompile exists, with zero changes to the
/// bridge logic — that is the whole point of the pluggable gate.
///
/// This is a clean-room reference written against the public FIPS-204 / EIP-8051 specs.
/// It is a teaching artifact: not audited, not for production.
contract MlDsaAttestationVerifier is IAttestationVerifier {
    // EIP-8051 byte lengths for the EVM-optimized verifier (VERIFY_MLDSA_ETH at 0x13).
    // message(32) || signature(2420) || expandedPublicKey(20512) = 22964 bytes input;
    /// output is 32 bytes, 1 (valid) or 0 (invalid).
    uint256 internal constant SIG_LEN = 2420;
    uint256 internal constant PK_LEN = 20512;

    /// Canonical EIP-8051 precompile (EVM-optimized). Overridable in the constructor so
    /// tests can point at a mock and so deployments on non-canonical chains can adapt.
    address public constant EIP8051_VERIFY_MLDSA_ETH = address(0x13);

    address public immutable precompile;
    address public owner;

    /// keccak256 of the authorized operator's 20512-byte expanded ML-DSA public key.
    /// We commit to the hash on-chain and take the full key in the attestation calldata,
    /// rather than storing 20KB of key in contract storage.
    bytes32 public authorizedKeyHash;

    error NotOwner();
    error ZeroAddress();

    event KeyAuthorized(bytes32 indexed keyHash);
    event OwnerTransferred(address indexed from, address indexed to);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param owner_ admin that can rotate the authorized key.
    /// @param keyHash keccak256 of the authorized expanded ML-DSA public key (or 0 to set later).
    /// @param precompile_ EIP-8051 precompile address; pass address(0) to use the canonical 0x13.
    constructor(address owner_, bytes32 keyHash, address precompile_) {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        authorizedKeyHash = keyHash;
        precompile = precompile_ == address(0) ? EIP8051_VERIFY_MLDSA_ETH : precompile_;
        if (keyHash != bytes32(0)) emit KeyAuthorized(keyHash);
    }

    function setAuthorizedKey(bytes32 keyHash) external onlyOwner {
        authorizedKeyHash = keyHash;
        emit KeyAuthorized(keyHash);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @inheritdoc IAttestationVerifier
    /// @param attestation abi.encode(bytes expandedPublicKey, bytes signature).
    /// @dev Never reverts — a malformed attestation, wrong key, or bad signature all
    /// resolve to `false`, so callers treat "not authorized" as one rejection path
    /// (same contract as EcdsaAttestationVerifier). The crypto itself is the
    /// precompile's responsibility; this contract guarantees only that a `true` result
    /// means the precompile verified the *authorized* key's signature over *this* digest.
    function verify(bytes32 digest, bytes calldata attestation) external view returns (bool) {
        try this.checkAttestation(digest, attestation) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    /// @dev External so `verify` can wrap it in try/catch to neutralize decode reverts.
    /// Restricted to self-calls; not part of the public surface.
    function checkAttestation(bytes32 digest, bytes calldata attestation) external view returns (bool) {
        require(msg.sender == address(this), "self only");

        (bytes memory pubKey, bytes memory signature) = abi.decode(attestation, (bytes, bytes));
        if (pubKey.length != PK_LEN || signature.length != SIG_LEN) return false;
        if (keccak256(pubKey) != authorizedKeyHash) return false;

        // EIP-8051 VERIFY_MLDSA_ETH input: message(32) || signature(2420) || pubKey(20512).
        bytes memory input = abi.encodePacked(digest, signature, pubKey);

        (bool callOk, bytes memory ret) = precompile.staticcall(input);
        if (!callOk || ret.length < 32) return false;
        return abi.decode(ret, (uint256)) == 1;
    }
}
