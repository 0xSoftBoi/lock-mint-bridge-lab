// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationVerifier} from "./IAttestationVerifier.sol";

/// @title EcdsaAttestationVerifier
/// @notice The EVM-destination gate: an attestation is a 65-byte ECDSA signature by a
/// whitelisted operator over the EIP-191 personal-sign hash of the digest. This is the
/// "interim" path in the writeup — genuinely secure against a classical adversary, and
/// inheriting post-quantum integrity transitively from the home chain rather than
/// pretending to verify a lattice signature on-chain.
contract EcdsaAttestationVerifier is IAttestationVerifier {
    address public owner;
    mapping(address => bool) public isOperator;

    error NotOwner();
    error ZeroAddress();

    event OperatorSet(address indexed operator, bool allowed);
    event OwnerTransferred(address indexed from, address indexed to);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address owner_, address[] memory operators) {
        if (owner_ == address(0)) revert ZeroAddress();
        owner = owner_;
        for (uint256 i; i < operators.length; ++i) {
            isOperator[operators[i]] = true;
            emit OperatorSet(operators[i], true);
        }
    }

    function setOperator(address operator, bool allowed) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress();
        isOperator[operator] = allowed;
        emit OperatorSet(operator, allowed);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnerTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @inheritdoc IAttestationVerifier
    /// @dev Returns false (never reverts) on a malformed or wrong signature, so callers
    /// uniformly treat "not a valid attestation" as a single rejection path.
    function verify(bytes32 digest, bytes calldata attestation) external view returns (bool) {
        if (attestation.length != 65) return false;
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(attestation.offset)
            s := calldataload(add(attestation.offset, 32))
            v := byte(0, calldataload(add(attestation.offset, 64)))
        }
        // Reject high-s (EIP-2 malleability) and bad v so one lock can't yield two
        // distinct-but-valid signatures.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }
        if (v != 27 && v != 28) return false;

        address signer = ecrecover(ethHash, v, r, s);
        return signer != address(0) && isOperator[signer];
    }
}
