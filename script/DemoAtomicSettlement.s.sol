// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";
import {WrappedToken} from "../src/WrappedToken.sol";
import {SourceVault, IERC20} from "../src/SourceVault.sol";
import {MintAdapter} from "../src/MintAdapter.sol";
import {MlDsaAttestationVerifier} from "../src/MlDsaAttestationVerifier.sol";
import {MlDsaPrecompileMock} from "../test/mocks/MlDsaPrecompileMock.sol";

/// @title DemoAtomicSettlement
/// @notice A runnable, end-to-end **post-quantum compliant settlement**: Alice bridges 100
/// tokens out and back, with every value-moving step gated by an **ML-DSA** (FIPS-204)
/// signature verified through the EIP-8051 precompile. Demonstrates the three properties
/// at once:
///   - **compliant**: a mint/unlock only happens against an authorized operator signature;
///     a forged one mints nothing.
///   - **atomic**: a commit reaches exactly one terminal outcome — UNLOCKED xor REFUNDED.
///   - **solvent**: wrapped supply ≤ locked collateral at every step.
///
/// Run locally:  `forge script script/DemoAtomicSettlement.s.sol -vv`
///
/// Honest boundary: ML-DSA verification is the EIP-8051 precompile's job (address 0x13 on
/// a chain that has it). No public testnet ships it yet, so here it's a deployed stand-in
/// that accepts the operator's exact signed tuple — the *bridge* logic (binding, gating,
/// atomicity, solvency) is exercised for real.
contract DemoAtomicSettlement is Script {
    uint256 constant SRC_CHAIN = 1;
    uint256 constant AMOUNT = 100 ether;

    MockERC20 asset;
    WrappedToken wrapped;
    SourceVault vault;
    MintAdapter adapter;
    MlDsaAttestationVerifier verifier;
    MlDsaPrecompileMock precompile;

    address owner = address(0xB0B);
    address admin = address(0xADADADAD);
    address alice = address(0xA11CE);
    address attacker = address(0xBADBAD);

    bytes opPubKey; // 20512-byte ML-DSA-65 expanded public key
    bytes opSig; // 2420-byte ML-DSA signature (opaque; the precompile checks it)

    function run() external {
        _setup();
        bytes32 commitId = _step1_lock();
        _step2_mint(commitId);
        _step3_adversaryBlocked();
        _step4_burn();
        _step5_unlock(commitId);
        _step6_atomicity(commitId);
        console2.log("");
        console2.log(unicode"== DEMO COMPLETE: PQ-gated settlement, atomic, solvent throughout ==");
    }

    function _setup() internal {
        opPubKey = _fill(20512, 0x11);
        opSig = _fill(2420, 0x22);

        asset = new MockERC20();
        precompile = new MlDsaPrecompileMock(); // stands in for the EIP-8051 precompile (0x13)
        verifier = new MlDsaAttestationVerifier(owner, keccak256(opPubKey), address(precompile));

        // token↔adapter is circular: deploy token with a placeholder minter, then rotate to
        // the adapter (script contracts can't use address(this) as a stable address).
        wrapped = new WrappedToken("Wrapped Mock", "wMOCK", admin, address(0x7E11));
        vault = new SourceVault(IERC20(address(asset)), verifier, owner);
        adapter = new MintAdapter(wrapped, verifier, owner);
        vm.prank(admin);
        wrapped.setMinter(address(adapter));

        asset.mint(alice, AMOUNT);
        vm.prank(alice);
        asset.approve(address(vault), type(uint256).max);

        console2.log(unicode"verifier = post-quantum ML-DSA gate (EIP-8051), authorized 1 operator key");
        console2.log("");
    }

    function _step1_lock() internal returns (bytes32 commitId) {
        vm.prank(alice);
        commitId = vault.lock(AMOUNT, block.chainid, alice);
        console2.log(unicode"1. LOCK     alice locks 100 on source");
        _invariant();
    }

    function _step2_mint(bytes32 commitId) internal {
        bytes32 d = adapter.digest(commitId, alice, AMOUNT, SRC_CHAIN);
        bytes memory att = _operatorAttest(d); // operator produces a valid ML-DSA signature
        adapter.mint(commitId, alice, AMOUNT, SRC_CHAIN, att);
        console2.log(unicode"2. MINT     operator's ML-DSA attestation verified -> 100 wMOCK minted");
        _invariant();
    }

    function _step3_adversaryBlocked() internal {
        // No valid signature registered for this action: the precompile rejects it.
        bytes memory forged = abi.encode(opPubKey, opSig);
        try adapter.mint(keccak256("evil"), attacker, 1000 ether, SRC_CHAIN, forged) {
            revert("adversary mint should have failed");
        } catch {
            console2.log(unicode"3. ATTACK   forged mint REVERTED (gate held) -> adversary minted 0");
        }
        _invariant();
    }

    function _step4_burn() internal {
        vm.prank(alice);
        adapter.burn(AMOUNT, block.chainid, alice);
        console2.log(unicode"4. BURN     alice burns 100 wMOCK to start the return leg");
        _invariant();
    }

    function _step5_unlock(bytes32 commitId) internal {
        bytes32 d = vault.digest(vault.UNLOCK_DOMAIN(), commitId, alice, AMOUNT, SRC_CHAIN);
        bytes memory att = _operatorAttest(d);
        vault.unlock(commitId, alice, SRC_CHAIN, att);
        console2.log(unicode"5. UNLOCK   operator's ML-DSA attestation verified -> 100 returned to alice");
        _invariant();
    }

    function _step6_atomicity(bytes32 commitId) internal {
        // Even WITH a valid refund signature, the commit is already UNLOCKED — one outcome.
        bytes32 d = vault.digest(vault.REFUND_DOMAIN(), commitId, alice, AMOUNT, SRC_CHAIN);
        bytes memory att = _operatorAttest(d);
        try vault.refund(commitId, SRC_CHAIN, att) {
            revert("refund after unlock should have failed");
        } catch {
            console2.log(unicode"6. ATOMIC   refund-after-unlock REVERTED -> exactly one terminal outcome");
        }
    }

    /// The operator "signs" the digest: register the exact (digest || sig || pubKey) tuple the
    /// EIP-8051 precompile must accept, and hand the verifier the attestation it will forward.
    function _operatorAttest(bytes32 d) internal returns (bytes memory) {
        precompile.setValid(abi.encodePacked(d, opSig, opPubKey));
        return abi.encode(opPubKey, opSig);
    }

    function _invariant() internal view {
        uint256 supply = wrapped.totalSupply();
        uint256 locked = vault.totalLocked();
        require(supply <= locked, "INVARIANT BROKEN: supply > collateral");
        console2.log("            supply <= collateral:", supply / 1e18, "<=", locked / 1e18);
    }

    function _fill(uint256 n, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) {
            b[i] = bytes1(uint8((i * 31 + seed) & 0xff));
        }
    }
}
