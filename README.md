# lock-mint-bridge-lab

A small, annotated lock-and-mint bridge built **for auditors** — the one accounting
invariant, the attestation-gate fix that holds it, and runnable reproductions of the
bridge hacks that didn't have it.

It's the public companion to two write-ups:

- [Auditing my own bridge: from "mints money from nothing" to all-criticals-closed](https://0xsoftboi.github.io/blog/auditing-my-own-bridge/)
- [The post-quantum proof that Shor breaks anyway](https://0xsoftboi.github.io/blog/post-quantum-proof-shor-breaks-anyway/)

This is a clean-room teaching artifact — minimal, self-contained, no external
dependencies beyond `forge-std`. It is **not** audited and **not** for production.

## The whole thing in one line

A lock-and-mint bridge is one accounting invariant:

> wrapped tokens minted on the destination must never exceed the collateral locked on the source.

```solidity
function invariant_supply_le_collateral() public view {
    assertLe(wrapped.totalSupply(), vault.totalLocked());
}
```

Break it and the bridge prints money. The classic way to break it: trust a relayer to
say "a lock happened" with no sound on-chain proof that it did. That's the
Ronin / Wormhole family — the most expensive bug class in the space.

## The fix: an attestation gate

Every value-moving call (`mint`, `unlock`, `refund`) passes through a pluggable
verifier over a digest that binds **all** the parameters plus the chain id and the
contract address:

```solidity
bytes32 digest = keccak256(abi.encode(
    DOMAIN, block.chainid, address(this),
    commitId, recipient, amount, sourceChainId
));
require(verifier.verify(digest, attestation), "unauthorized");
```

- Binding `address(this)` stops a signature replaying across deployments; `block.chainid`
  stops it crossing chains; `commitId` stops a second mint; the domain tag stops an
  unlock signature being reused as a refund.
- The verifier is **pluggable** ([`IAttestationVerifier`](src/IAttestationVerifier.sol)):
  ECDSA on EVM destinations ([`EcdsaAttestationVerifier`](src/EcdsaAttestationVerifier.sol)),
  or a post-quantum **ML-DSA** verifier ([`MlDsaAttestationVerifier`](src/MlDsaAttestationVerifier.sol))
  that delegates the lattice math to the [EIP-8051](https://eips.ethereum.org/EIPS/eip-8051)
  precompile — without touching the vault/adapter logic. (Why a lattice signature, and why
  *not* wrapped in a SNARK, is the subject of the second post.) The interface is written up
  as a draft ERC: [`spec/ERC-DRAFT-pq-attestation-verifier.md`](spec/ERC-DRAFT-pq-attestation-verifier.md).
- A `commitId` can reach at most one terminal outcome `{UNLOCKED, REFUNDED}`, enforced
  on-chain — that's the cross-domain "minted **and** refunded" double-spend closed.

## What's here

| Contract | Role |
|---|---|
| [`SourceVault`](src/SourceVault.sol) | Locks collateral; authority for `totalLocked`. Unlock/refund are gated and mutually exclusive. |
| [`MintAdapter`](src/MintAdapter.sol) | Mints the wrapped token against an attestation; replay-protected by `commitId`; burns to start the return leg. |
| [`WrappedToken`](src/WrappedToken.sol) | Destination ERC-20. Admin ≠ minter (an admin key must not be a silent parallel minter). |
| [`EcdsaAttestationVerifier`](src/EcdsaAttestationVerifier.sol) | Operator-whitelist ECDSA gate (EIP-2 low-s, no zero signer). |
| [`MlDsaAttestationVerifier`](src/MlDsaAttestationVerifier.sol) | Post-quantum gate: commits to an ML-DSA-65 (FIPS-204) public-key hash; forwards to the EIP-8051 precompile. Clean-room reference. |

## Tests (`forge test`)

- **`test/invariant/Supply.invariant.t.sol`** — drives the bridge with a handler that
  models an honest operator **and** an adversarial relayer, over **512 runs × depth 100**:
  - `invariant_supply_le_collateral` — supply never exceeds locked collateral.
  - `invariant_adversary_minted_nothing` — an adversary armed only with forged
    attestations mints exactly zero.
- **`test/Bridge.t.sol`** — unit tests for the gate (forged / junk / tampered-amount /
  replay all rejected), the unlock-XOR-refund outcome, and the admin≠minter rule. Plus
  **`test_mutation_gateOff_breaksSupplyInvariant`**: disable the gate (revert the fix)
  and the same forged mint succeeds and breaks the invariant in one call — a test that
  can't be made to fail by removing the fix isn't testing the fix.
- **`test/historical/Historical.t.sol`** — minimal reproductions showing the gate
  rejects each move: **Ronin** (rotated-out / non-operator key), **Wormhole**
  (no unverified mint path), **Nomad** (zero/default proof authorizes nothing).

```
forge install   # pulls forge-std
forge test      # 29 tests (incl. the ML-DSA verifier); invariants at 512 × 100
```

## Live demo: post-quantum atomic settlement

A runnable end-to-end settlement — Alice bridges 100 out and back — with every value-moving
step gated by an **ML-DSA** ([`MlDsaAttestationVerifier`](src/MlDsaAttestationVerifier.sol))
signature. Shows all three properties at once: **compliant** (a forged attestation mints
nothing), **atomic** (one terminal outcome per commit), **solvent** (supply ≤ collateral
throughout).

```
forge script script/DemoAtomicSettlement.s.sol -vv
```

```text
== Logs ==
  verifier = post-quantum ML-DSA gate (EIP-8051), authorized 1 operator key
  1. LOCK     alice locks 100 on source
              supply <= collateral: 0 <= 100
  2. MINT     operator's ML-DSA attestation verified -> 100 wMOCK minted
              supply <= collateral: 100 <= 100
  3. ATTACK   forged mint REVERTED (gate held) -> adversary minted 0
              supply <= collateral: 100 <= 100
  4. BURN     alice burns 100 wMOCK to start the return leg
              supply <= collateral: 0 <= 100
  5. UNLOCK   operator's ML-DSA attestation verified -> 100 returned to alice
              supply <= collateral: 0 <= 0
  6. ATOMIC   refund-after-unlock REVERTED -> exactly one terminal outcome
  == DEMO COMPLETE: PQ-gated settlement, atomic, solvent throughout ==
```

Honest boundary: ML-DSA verification is the EIP-8051 precompile's job (`0x13` on a chain that
has it). No public testnet ships it yet, so the script uses a deployed stand-in that accepts the
operator's exact signed tuple — the **bridge** logic (binding, gating, atomicity, solvency) runs
for real.

## Scope / honesty

The supply≤collateral guarantee is, end-to-end, an *operator-coordination* property
that the gate makes **enforceable on-chain** — a rogue relayer can't unlock or refund
without an operator signature — not a property the contracts can prove about events on
another chain by themselves. The historical reproductions are deliberately minimal
stand-ins for the real exploits, not faithful forks. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
