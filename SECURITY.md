# Security notes

**This is a teaching artifact, not production code.** It has not been audited. Do not
deploy it to hold real funds. Its purpose is to make the ideas in the two linked
write-ups concrete and runnable.

## Threat model (what the gate does and does not buy you)

- **Trust assumption.** Minting, unlocking, and refunding are authorized by a
  whitelisted operator's signature over a parameter-binding digest. The system is only
  as honest as that operator set; the gate's job is to make sure *nothing of value moves
  without a valid operator attestation* and that an attestation cannot be replayed or
  retargeted.
- **What's enforced on-chain:**
  - No mint / unlock / refund without a valid attestation over the exact
    `(domain, chainid, address(this), commitId, recipient, amount, sourceChainId)`.
  - Replay protection: one mint per `commitId`; signature non-malleability (EIP-2 low-s);
    no zero/`address(0)` signer.
  - A `commitId` reaches at most one of `{UNLOCKED, REFUNDED}` — a rogue relayer cannot
    refund a commit that was unlocked, or vice versa.
- **What is an operator-coordination property, not a contract proof:** the end-to-end
  "wrapped supply ≤ collateral locked" holds because an honest operator only signs a
  mint for a real lock and only signs an unlock after the matching burn. The source-chain
  vault cannot itself observe destination-chain events. The gate makes that coordination
  *enforceable* (no value moves without the operator) but does not eliminate the need to
  trust the operator set. A production system hardens this with light-client / proof
  verification, an optimistic challenge window, multiple independent attesters, etc.

## Known simplifications

- The historical reproductions (Ronin / Wormhole / Nomad) are minimal stand-ins that
  exercise the *defense*, not faithful forks of the exploited contracts.
- No fee logic, pausing, upgradeability, multi-asset accounting, or gas hardening — all
  intentionally omitted to keep the invariant legible.
- ECDSA verification only; the post-quantum (ML-DSA) path is described in the write-ups
  but not implemented here (it needs a chain-level precompile).

## Reporting

This repo isn't deployed and holds no funds, so there's nothing to exploit in
production. If you spot a correctness bug in the teaching code, open an issue.
