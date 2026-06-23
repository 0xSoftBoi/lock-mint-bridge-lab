---
title: Pluggable Attestation Verifier (post-quantum capable)
description: A minimal, scheme-agnostic interface for the signature/attestation gate that authorizes value-moving cross-chain actions, so bridges can migrate ECDSA → ML-DSA without touching application logic.
author: Tsolmondorj Natsagdorj (@0xSoftBoi)
discussions-to: https://ethereum-magicians.org/  # TODO: open a thread before submission
status: Draft
type: Standards Track
category: ERC
created: 2026-06-23
requires: 8051
---

> Draft for discussion — not yet submitted to the EIPs repository. Reference
> implementations live in this repo (`src/EcdsaAttestationVerifier.sol`,
> `src/MlDsaAttestationVerifier.sol`).

## Abstract

A one-method interface, `IAttestationVerifier`, for the gate that decides whether a
given action (a bridge mint/unlock/refund, a settlement, a withdrawal) is authorized.
The gate takes a 32-byte `digest` that binds all parameters of the action and an opaque
`attestation`, and returns a boolean. By making the **signature scheme opaque to the
caller**, the same vault/adapter logic runs unchanged whether the attestation is an
ECDSA signature today or an **ML-DSA** (FIPS-204) signature verified via the
[EIP-8051](https://eips.ethereum.org/EIPS/eip-8051) precompile after the post-quantum
transition.

## Motivation

Cross-chain bridges are the most exploited primitive in the ecosystem, and every
value-moving call ultimately rests on verifying that some off-chain/cross-chain event was
attested by an authorized party. Two problems recur:

1. **Coupling.** Verification logic is hand-rolled inside each adapter, so changing the
   signature scheme means rewriting the security-critical path.
2. **Quantum migration debt.** ECDSA secp256k1 and BLS are forgeable under Shor's
   algorithm. Of the named institutional digital-asset programs, ~0 have a disclosed
   post-quantum roadmap. When ML-DSA precompiles (EIP-8051) ship, bridges need a way to
   swap the verifier **without** re-auditing the vault.

A standard pluggable verifier decouples *what authorizes an action* from *what the action
does*, and makes the ECDSA → post-quantum migration a one-line deployment change.

## Specification

The key words MUST, MUST NOT, SHOULD are to be interpreted as in RFC 2119.

```solidity
interface IAttestationVerifier {
    /// @param digest      A hash binding ALL parameters of the action, and at minimum
    ///                    the verifying contract address and chain id (replay safety).
    /// @param attestation Opaque proof bytes (scheme-specific).
    /// @return ok         true iff `attestation` is a valid authorization of `digest`.
    function verify(bytes32 digest, bytes calldata attestation) external view returns (bool ok);
}
```

- `verify` MUST be `view` and MUST NOT revert on a malformed, unauthorized, or invalid
  `attestation`; it MUST return `false` instead, so callers have a single rejection path.
- `digest` MUST bind the verifying contract address and chain id, so an attestation
  cannot be replayed across deployments or chains. It SHOULD additionally bind a unique
  action id (e.g. a `commitId`) and all economic parameters.
- A conforming verifier MAY implement any scheme. A **post-quantum** verifier SHOULD
  delegate the lattice/hash-based verification to a precompile (e.g. EIP-8051
  `VERIFY_MLDSA_ETH` at `0x13`) rather than implementing it in the EVM.

### Attestation encodings (recommended)

- ECDSA: `attestation = abi.encodePacked(r, s, v)` (65 bytes) over the EIP-191 hash of `digest`.
- ML-DSA (EIP-8051): `attestation = abi.encode(bytes expandedPublicKey, bytes signature)`;
  the verifier commits to `keccak256(expandedPublicKey)` on-chain and forwards
  `digest || signature || expandedPublicKey` to the precompile.

## Rationale

- **Single method, opaque bytes.** Anything richer (per-scheme structs) re-introduces the
  coupling this standard removes. `bytes` keeps the adapter scheme-blind.
- **`view` + no-revert.** Lets the gate be probed and composed, and gives callers one
  uniform `false` path (matches existing reference verifiers in the wild).
- **Digest binding is mandated, not the digest contents.** Different protocols bind
  different parameters; the standard fixes only the replay-safety floor (address + chainid).

## Backwards Compatibility

Purely additive. Existing ECDSA gates already match this shape; ERC-1271 verifiers can be
wrapped trivially.

## Reference Implementation

- `EcdsaAttestationVerifier` — operator-whitelisted ECDSA over the EIP-191 digest.
- `MlDsaAttestationVerifier` — commits to an ML-DSA-65 public-key hash; forwards to the
  EIP-8051 precompile; clean-room from FIPS-204 / EIP-8051. Tests prove input encoding,
  digest binding, key authorization, and malformed-input rejection with the precompile mocked.

## Security Considerations

- The gate is only as strong as the scheme behind it: an ECDSA verifier is classically
  secure but **quantum-vulnerable**; migrate to an EIP-8051-backed verifier before a
  cryptographically-relevant quantum computer exists.
- `digest` MUST bind `address(this)` and `block.chainid`, or signatures replay across
  deployments/chains.
- A post-quantum verifier inherits the precompile's correctness and gas; verify the
  precompile is present and canonical on the target chain.

## References

- [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051): ML-DSA verification precompile.
- [EIP-7885](https://eips.ethereum.org/EIPS/eip-7885): NTT precompile (reduces ML-DSA cost).
- NIST FIPS-204 (ML-DSA / Dilithium).

## Copyright

Released under CC0.
