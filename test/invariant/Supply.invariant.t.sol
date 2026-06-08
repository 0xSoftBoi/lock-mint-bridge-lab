// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {EcdsaAttestationVerifier} from "../../src/EcdsaAttestationVerifier.sol";
import {WrappedToken} from "../../src/WrappedToken.sol";
import {SourceVault, IERC20} from "../../src/SourceVault.sol";
import {MintAdapter} from "../../src/MintAdapter.sol";

/// Drives the bridge as a fuzzer would: an HONEST operator (signs only valid state
/// transitions) plus an ADVERSARIAL relayer (submits forged attestations, which must
/// always revert). Every commit walks lock -> mint -> burn -> unlock, or lock -> refund;
/// the operator never signs a refund for a commit it already minted (the cross-domain
/// XOR is an operator-coordination property the gate makes enforceable).
contract Handler is Test {
    SourceVault vault;
    MintAdapter adapter;
    WrappedToken wrapped;
    MockERC20 asset;
    uint256 opPk;
    address user = address(0x5E1F);
    uint256 constant SRC = 1;

    enum S {
        LOCKED,
        MINTED,
        BURNED,
        UNLOCKED,
        REFUNDED
    }

    struct Item {
        bytes32 id;
        uint256 amount;
        S state;
    }

    Item[] public items;
    uint256 public adversaryMintedSupply; // must stay 0

    constructor(SourceVault v, MintAdapter a, WrappedToken w, MockERC20 t, uint256 pk) {
        vault = v;
        adapter = a;
        wrapped = w;
        asset = t;
        opPk = pk;
    }

    function _sign(bytes32 digest) internal view returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(opPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _pick(S want, uint256 seed) internal view returns (bool found, uint256 idx) {
        uint256 n = items.length;
        if (n == 0) return (false, 0);
        for (uint256 i; i < n; ++i) {
            uint256 j = addmod(seed, i, n); // overflow-safe (seed can be ~2**256)
            if (items[j].state == want) return (true, j);
        }
        return (false, 0);
    }

    function lock(uint256 amount) external {
        amount = bound(amount, 1, 1e24);
        asset.mint(user, amount);
        vm.startPrank(user);
        asset.approve(address(vault), amount);
        bytes32 id = vault.lock(amount, block.chainid, user);
        vm.stopPrank();
        items.push(Item({id: id, amount: amount, state: S.LOCKED}));
    }

    function mintFor(uint256 seed) external {
        (bool ok, uint256 i) = _pick(S.LOCKED, seed);
        if (!ok) return;
        Item storage it = items[i];
        bytes memory att = _sign(adapter.digest(it.id, user, it.amount, SRC));
        adapter.mint(it.id, user, it.amount, SRC, att);
        it.state = S.MINTED;
    }

    function burnFor(uint256 seed) external {
        (bool ok, uint256 i) = _pick(S.MINTED, seed);
        if (!ok) return;
        Item storage it = items[i];
        vm.prank(user);
        adapter.burn(it.amount, SRC, user);
        it.state = S.BURNED;
    }

    function unlockFor(uint256 seed) external {
        (bool ok, uint256 i) = _pick(S.BURNED, seed);
        if (!ok) return;
        Item storage it = items[i];
        bytes memory att = _sign(vault.digest(vault.UNLOCK_DOMAIN(), it.id, user, it.amount, SRC));
        vault.unlock(it.id, user, SRC, att);
        it.state = S.UNLOCKED;
    }

    function refundFor(uint256 seed) external {
        (bool ok, uint256 i) = _pick(S.LOCKED, seed); // only un-minted commits
        if (!ok) return;
        Item storage it = items[i];
        bytes memory att = _sign(vault.digest(vault.REFUND_DOMAIN(), it.id, user, it.amount, SRC));
        vault.refund(it.id, SRC, att);
        it.state = S.REFUNDED;
    }

    /// The adversary: forge a mint with junk/wrong attestation. Must always revert; if it
    /// ever mints, record it so the invariant catches the unbacked supply.
    function adversaryMint(uint256 seed, bytes calldata junk) external {
        bytes32 fakeId = keccak256(abi.encode("forge", seed));
        if (adapter.minted(fakeId)) return;
        uint256 before = wrapped.totalSupply();
        try adapter.mint(fakeId, address(0xBAD), 1e30, SRC, junk) {
            adversaryMintedSupply += wrapped.totalSupply() - before;
        } catch {}
    }
}

contract SupplyInvariantTest is Test {
    MockERC20 asset;
    EcdsaAttestationVerifier verifier;
    WrappedToken wrapped;
    SourceVault vault;
    MintAdapter adapter;
    Handler handler;

    uint256 constant OP_PK = 0xA11CE;

    function setUp() public {
        address operator = vm.addr(OP_PK);
        address[] memory ops = new address[](1);
        ops[0] = operator;

        asset = new MockERC20();
        verifier = new EcdsaAttestationVerifier(address(this), ops);
        wrapped = new WrappedToken("Wrapped Mock", "wMOCK", address(0xAD), address(this));
        vault = new SourceVault(IERC20(address(asset)), verifier, address(this));
        adapter = new MintAdapter(wrapped, verifier, address(this));
        vm.prank(address(0xAD));
        wrapped.setMinter(address(adapter));

        handler = new Handler(vault, adapter, wrapped, asset, OP_PK);
        targetContract(address(handler));
    }

    /// The one big invariant: no more wrapped tokens exist than collateral locked.
    function invariant_supply_le_collateral() public view {
        assertLe(wrapped.totalSupply(), vault.totalLocked());
    }

    /// The gate holds: an adversary using only forged attestations mints nothing.
    function invariant_adversary_minted_nothing() public view {
        assertEq(handler.adversaryMintedSupply(), 0);
    }
}
