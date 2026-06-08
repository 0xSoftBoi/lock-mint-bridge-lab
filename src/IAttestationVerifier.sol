// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAttestationVerifier
/// @notice The pluggable "gate" every value-moving call passes through. A bridge is
/// only as sound as the proof that the cross-chain event it acts on actually happened;
/// this interface is where that proof is checked. Swap the implementation per chain —
/// ECDSA on EVM destinations, a post-quantum lattice verifier on a chain you control —
/// without touching the vault/adapter logic.
interface IAttestationVerifier {
    /// @param digest  A hash that binds ALL parameters of the action (see the adapter/
    ///                vault: domain, chainid, contract address, commitId, recipient,
    ///                amount, sourceChainId). Binding the address + chainid is what
    ///                stops a signature being replayed on another contract or chain.
    /// @param attestation Opaque proof bytes (e.g. an operator signature).
    /// @return ok true iff `attestation` is a valid authorization of `digest`.
    function verify(bytes32 digest, bytes calldata attestation) external view returns (bool ok);
}
