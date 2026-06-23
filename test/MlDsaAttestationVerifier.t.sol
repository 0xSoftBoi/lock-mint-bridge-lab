// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MlDsaAttestationVerifier} from "../src/MlDsaAttestationVerifier.sol";
import {MlDsaPrecompileMock} from "./mocks/MlDsaPrecompileMock.sol";

/// Tests the verifier's responsibilities — EIP-8051 input encoding, digest binding, key
/// authorization, malformed-input rejection, and the "never reverts" contract — with the
/// lattice math mocked (that lives in the precompile on a real EIP-8051 chain).
contract MlDsaAttestationVerifierTest is Test {
    MlDsaAttestationVerifier verifier;
    MlDsaPrecompileMock precompile;

    address owner = address(0xB0B);

    uint256 constant SIG_LEN = 2420;
    uint256 constant PK_LEN = 20512;

    bytes32 constant DIGEST = keccak256("bind: domain|chainid|adapter|commitId|recipient|amount|src");
    bytes pubKey;
    bytes signature;

    function setUp() public {
        precompile = new MlDsaPrecompileMock();

        // Structural KAT placeholders: correct EIP-8051 lengths, deterministic content.
        // Replace with real NIST FIPS-204 ML-DSA-65 KAT bytes for a full crypto KAT —
        // the exact-match mock and the verifier encoding are unchanged.
        pubKey = _fill(PK_LEN, 0x11);
        signature = _fill(SIG_LEN, 0x22);

        verifier = new MlDsaAttestationVerifier(owner, keccak256(pubKey), address(precompile));

        // Register the one valid tuple the precompile should accept: msg || sig || pubKey.
        precompile.setValid(abi.encodePacked(DIGEST, signature, pubKey));
    }

    function _attestation(bytes memory pk, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encode(pk, sig);
    }

    function test_accepts_valid_attestation_over_digest() public view {
        assertTrue(verifier.verify(DIGEST, _attestation(pubKey, signature)));
    }

    function test_rejects_wrong_digest() public view {
        bytes32 other = keccak256("different action");
        assertFalse(verifier.verify(other, _attestation(pubKey, signature)));
    }

    function test_rejects_tampered_signature() public view {
        bytes memory sig = bytes.concat(signature);
        sig[0] = bytes1(uint8(sig[0]) ^ 0x01);
        assertFalse(verifier.verify(DIGEST, _attestation(pubKey, sig)));
    }

    function test_rejects_unauthorized_key() public view {
        bytes memory otherKey = _fill(PK_LEN, 0x33); // correct length, wrong key
        assertFalse(verifier.verify(DIGEST, _attestation(otherKey, signature)));
    }

    function test_rejects_malformed_signature_length() public view {
        bytes memory shortSig = _fill(SIG_LEN - 1, 0x22);
        assertFalse(verifier.verify(DIGEST, _attestation(pubKey, shortSig)));
    }

    function test_rejects_malformed_pubkey_length() public view {
        bytes memory shortPk = _fill(PK_LEN - 1, 0x11);
        assertFalse(verifier.verify(DIGEST, _attestation(shortPk, signature)));
    }

    function test_never_reverts_on_garbage_attestation() public view {
        // Not abi-decodable → the internal decode reverts → verify catches → false.
        assertFalse(verifier.verify(DIGEST, hex"deadbeef"));
        assertFalse(verifier.verify(DIGEST, ""));
    }

    function test_encodes_eip8051_input_layout() public view {
        // The precompile only accepts msg||sig||pubKey in that exact order/length; a
        // passing verify proves the verifier assembled the EIP-8051 input correctly.
        uint256 expectedLen = 32 + SIG_LEN + PK_LEN; // 22964
        assertEq(expectedLen, 22964);
        assertTrue(verifier.verify(DIGEST, _attestation(pubKey, signature)));
    }

    function test_only_owner_can_rotate_key() public {
        bytes32 newHash = keccak256("new key");
        vm.expectRevert(MlDsaAttestationVerifier.NotOwner.selector);
        verifier.setAuthorizedKey(newHash);

        vm.prank(owner);
        verifier.setAuthorizedKey(newHash);
        assertEq(verifier.authorizedKeyHash(), newHash);
    }

    function test_defaults_to_canonical_precompile_address() public {
        MlDsaAttestationVerifier v = new MlDsaAttestationVerifier(owner, bytes32(0), address(0));
        assertEq(v.precompile(), address(0x13));
    }

    /// Deterministic byte filler — cheap, no keccak per byte.
    function _fill(uint256 n, uint8 seed) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; ++i) {
            b[i] = bytes1(uint8((i * 31 + seed) & 0xff));
        }
    }
}
