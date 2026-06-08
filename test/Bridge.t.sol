// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {IAttestationVerifier} from "../src/IAttestationVerifier.sol";
import {EcdsaAttestationVerifier} from "../src/EcdsaAttestationVerifier.sol";
import {WrappedToken} from "../src/WrappedToken.sol";
import {SourceVault, IERC20} from "../src/SourceVault.sol";
import {MintAdapter} from "../src/MintAdapter.sol";

contract BridgeTest is Test {
    MockERC20 asset;
    EcdsaAttestationVerifier verifier;
    WrappedToken wrapped;
    SourceVault vault;
    MintAdapter adapter;

    uint256 constant OP_PK = 0xA11CE;
    address operator;
    address owner = address(0xB0B);
    address admin = address(0xAD); // token admin (NOT a minter)
    address alice = address(0xA1);
    uint256 constant SRC_CHAIN = 1;

    function setUp() public {
        operator = vm.addr(OP_PK);
        asset = new MockERC20();

        address[] memory ops = new address[](1);
        ops[0] = operator;
        verifier = new EcdsaAttestationVerifier(owner, ops);

        // token↔adapter is circular (adapter needs the token; token's minter is the
        // adapter). Deploy the token with a temporary minter, then have admin rotate
        // the minter to the adapter once it exists.
        wrapped = new WrappedToken("Wrapped Mock", "wMOCK", admin, address(this));
        vault = new SourceVault(IERC20(address(asset)), verifier, owner);
        adapter = new MintAdapter(wrapped, verifier, owner);
        vm.prank(admin);
        wrapped.setMinter(address(adapter));

        asset.mint(alice, 1_000 ether);
        vm.prank(alice);
        asset.approve(address(vault), type(uint256).max);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _lockAndMint(uint256 amount) internal returns (bytes32 commitId) {
        vm.prank(alice);
        commitId = vault.lock(amount, block.chainid, alice);
        bytes memory att = _sign(OP_PK, adapter.digest(commitId, alice, amount, SRC_CHAIN));
        adapter.mint(commitId, alice, amount, SRC_CHAIN, att);
    }

    // ── the gate ──────────────────────────────────────────────────────────
    function test_mint_withValidOperatorAttestation_succeeds() public {
        bytes32 c = _lockAndMint(100 ether);
        assertEq(wrapped.totalSupply(), 100 ether);
        assertTrue(adapter.minted(c));
    }

    function test_mint_forgedAttestation_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        // a signature by a NON-operator key
        bytes memory bad = _sign(0xBADBAD, adapter.digest(c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, alice, 100 ether, SRC_CHAIN, bad);
        assertEq(wrapped.totalSupply(), 0);
    }

    function test_mint_junkAttestation_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, alice, 100 ether, SRC_CHAIN, hex"deadbeef");
    }

    function test_mint_tamperedAmount_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        // operator signed for 100, attacker submits 1e30 — digest won't match
        bytes memory att = _sign(OP_PK, adapter.digest(c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, alice, 1e30, SRC_CHAIN, att);
    }

    function test_mint_replay_reverts() public {
        bytes32 c = _lockAndMint(100 ether);
        bytes memory att = _sign(OP_PK, adapter.digest(c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(MintAdapter.AlreadyMinted.selector);
        adapter.mint(c, alice, 100 ether, SRC_CHAIN, att);
    }

    // ── one outcome per commit (the cross-domain double-spend) ─────────────
    function test_refund_afterUnlock_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        bytes memory u = _sign(OP_PK, vault.digest(vault.UNLOCK_DOMAIN(), c, alice, 100 ether, SRC_CHAIN));
        vault.unlock(c, alice, SRC_CHAIN, u);
        bytes memory r = _sign(OP_PK, vault.digest(vault.REFUND_DOMAIN(), c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(SourceVault.BadStatus.selector);
        vault.refund(c, SRC_CHAIN, r);
    }

    function test_unlock_afterRefund_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        bytes memory r = _sign(OP_PK, vault.digest(vault.REFUND_DOMAIN(), c, alice, 100 ether, SRC_CHAIN));
        vault.refund(c, SRC_CHAIN, r);
        bytes memory u = _sign(OP_PK, vault.digest(vault.UNLOCK_DOMAIN(), c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(SourceVault.BadStatus.selector);
        vault.unlock(c, alice, SRC_CHAIN, u);
    }

    function test_unlock_forgedAttestation_reverts() public {
        vm.prank(alice);
        bytes32 c = vault.lock(100 ether, block.chainid, alice);
        bytes memory bad = _sign(0xBADBAD, vault.digest(vault.UNLOCK_DOMAIN(), c, alice, 100 ether, SRC_CHAIN));
        vm.expectRevert(SourceVault.Unauthorized.selector);
        vault.unlock(c, alice, SRC_CHAIN, bad);
    }

    // ── the token admin is not a parallel minter (P3-3 lesson) ─────────────
    function test_tokenAdmin_cannotMint() public {
        vm.prank(admin);
        vm.expectRevert(WrappedToken.NotMinter.selector);
        wrapped.mint(admin, 1 ether);
    }

    function test_tokenAdmin_cannotSetItselfMinter() public {
        vm.prank(admin);
        vm.expectRevert(WrappedToken.AdminCannotBeMinter.selector);
        wrapped.setMinter(admin);
    }

    // ── mutation / revert-fails: the gate is the fix ───────────────────────
    // Revert the fix (disable the attestation check) and the same forged mint that
    // reverts above now succeeds, breaking supply<=collateral in one call. A test that
    // can't be made to fail by removing the fix isn't testing the fix.
    function test_mutation_gateOff_breaksSupplyInvariant() public {
        assertEq(vault.totalLocked(), 0);
        vm.prank(owner);
        adapter.setAttestationRequired(false); // the mutation

        adapter.mint(keccak256("forged"), address(0xBAD), 1e30, SRC_CHAIN, hex"");

        assertGt(wrapped.totalSupply(), vault.totalLocked()); // invariant now violated
    }
}
