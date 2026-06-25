// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MlDsaPrecompileMock
/// @notice Stand-in for the EIP-8051 ML-DSA verification precompile (VERIFY_MLDSA_ETH).
/// Solidity tests can't run lattice verification, so the mock keys on the exact input
/// bytes: it returns 1 (valid) iff the raw calldata equals a registered valid tuple
/// `message(32) || signature(2420) || pubKey(20512)`, else 0. This lets the test prove
/// the *verifier's* responsibilities — EIP-8051 input layout, digest binding, key
/// authorization, malformed-input rejection — independent of the crypto, which is the
/// precompile's job on a real EIP-8051 chain. Swap in real NIST FIPS-204 KAT bytes and
/// the same exact-match check holds.
contract MlDsaPrecompileMock {
    /// The set of input tuples that verify as valid (keyed by keccak256 of the raw
    /// `message || signature || pubKey` bytes). A mapping rather than a single slot so
    /// multiple distinct attestations can be valid at once — needed to model concurrent
    /// operations and replay scenarios, not just a single sequential happy path.
    mapping(bytes32 => bool) public isValid;

    /// Register a valid input tuple (message || signature || pubKey).
    function setValid(bytes calldata input) external {
        isValid[keccak256(input)] = true;
    }

    /// EIP-8051 ABI: raw input in, 32-byte 1/0 out. View-safe (no state writes) so it
    /// works under STATICCALL.
    fallback(bytes calldata input) external returns (bytes memory) {
        return abi.encode(isValid[keccak256(input)] ? uint256(1) : uint256(0));
    }
}
