// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {EcdsaAttestationVerifier} from "../../src/EcdsaAttestationVerifier.sol";
import {WrappedToken} from "../../src/WrappedToken.sol";
import {SourceVault, IERC20} from "../../src/SourceVault.sol";
import {MintAdapter} from "../../src/MintAdapter.sol";

/// Minimal reproductions of well-documented bridge hacks, each showing the
/// attestation-gate design rejects the move that drained the real bridge. These are the
/// "Ronin / Wormhole family" the writeup names — externally-verified bridges that minted
/// on a say-so they never soundly verified.
contract HistoricalTest is Test {
    MockERC20 asset;
    EcdsaAttestationVerifier verifier;
    WrappedToken wrapped;
    SourceVault vault;
    MintAdapter adapter;

    uint256 constant OP_PK = 0xA11CE;
    uint256 constant ATTACKER_PK = 0xBADBAD;
    address operator;
    address attacker = address(0xBAD);
    uint256 constant SRC = 1;

    function setUp() public {
        operator = vm.addr(OP_PK);
        asset = new MockERC20();
        address[] memory ops = new address[](1);
        ops[0] = operator;
        verifier = new EcdsaAttestationVerifier(address(this), ops); // this = owner
        wrapped = new WrappedToken("Wrapped Mock", "wMOCK", address(0xAD), address(this));
        vault = new SourceVault(IERC20(address(asset)), verifier, address(this));
        adapter = new MintAdapter(wrapped, verifier, address(this));
        vm.prank(address(0xAD));
        wrapped.setMinter(address(adapter));
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    /// RONIN (Mar 2022, ~$625M): attackers controlled enough validator keys to sign a
    /// withdrawal themselves. Defense: only whitelisted operators are honored, and a
    /// compromised one can be rotated out — after which its signatures are dead.
    function test_ronin_rotatedOutOperatorCannotMint() public {
        bytes32 c = keccak256("commit-1");
        bytes32 d = adapter.digest(c, attacker, 1e30, SRC);

        // operator key is compromised; before rotation it would mint —
        verifier.setOperator(operator, false); // rotate the compromised key out

        bytes memory att = _sign(OP_PK, d);
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, attacker, 1e30, SRC, att);
        assertEq(wrapped.totalSupply(), 0);
    }

    /// An attacker's own key is simply not on the operator set.
    function test_ronin_nonValidatorKeyRejected() public {
        bytes32 c = keccak256("commit-2");
        bytes memory att = _sign(ATTACKER_PK, adapter.digest(c, attacker, 1e30, SRC));
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, attacker, 1e30, SRC, att);
    }

    /// WORMHOLE (Feb 2022, ~$326M): a bug let the attacker bypass the guardian signature
    /// check entirely and mint on an unsigned message. Defense: there is no mint path
    /// that skips `verify` — an empty/garbage attestation can never authorize.
    function test_wormhole_noUnverifiedMintPath() public {
        bytes32 c = keccak256("commit-3");
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, attacker, 1e30, SRC, hex""); // empty "proof"
        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, attacker, 1e30, SRC, hex"deadbeefdeadbeef"); // junk "proof"
        assertEq(wrapped.totalSupply(), 0);
    }

    /// NOMAD (Aug 2022, ~$190M): an upgrade left the trusted root at 0x00, so every proof
    /// verified against zero — "messages proven by default." Defense: a signature that
    /// recovers to the zero address is rejected, and the zero address can't be an
    /// operator, so a default/empty proof authorizes nothing.
    function test_nomad_zeroSignerRejected() public {
        bytes32 c = keccak256("commit-4");
        bytes32 d = adapter.digest(c, attacker, 1e30, SRC);
        // r=s=0 makes ecrecover return address(0); the verifier must not treat that as
        // an authorized operator even if address(0) were ever mistakenly whitelisted.
        bytes memory zeroSig = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        assertFalse(verifier.verify(d, zeroSig));

        vm.expectRevert(MintAdapter.Unauthorized.selector);
        adapter.mint(c, attacker, 1e30, SRC, zeroSig);
    }
}
