"""
Test BLS signature operations for EigenLayer smart contract interactions.

This module tests:
- BLS signature generation and aggregation
- Data structure conversion for contract calls
- Smart contract signature verification format
"""

import pytest
from dataclasses import dataclass
from typing import List, Tuple
from unittest.mock import Mock, patch
from eigensdk.crypto.bls.attestation import gen_random_bls_keys, new_key_pair_from_string, Signature


@dataclass
class G1Point:
    """Represents a point on the G1 curve (BN254)."""

    X: int
    Y: int

    def to_tuple(self) -> Tuple[int, int]:
        """Convert to tuple format for contract calls."""
        return self.X, self.Y


@dataclass
class G2Point:
    """Represents a point on the G2 curve (BN254)."""

    X: Tuple[int, int]
    Y: Tuple[int, int]

    def to_tuple(self) -> Tuple[List[int], List[int]]:
        """Convert to tuple format for contract calls."""
        return [self.X[0], self.X[1]], [self.Y[0], self.Y[1]]


@dataclass
class NonSignerStakesAndSignature:
    """Structure for contract signature verification."""

    nonSignerQuorumBitmapIndices: List[int]
    nonSignerPubkeys: List[G1Point]
    quorumApks: List[G1Point]
    apkG2: G2Point
    sigma: G1Point
    quorumApkIndices: List[int]
    totalStakeIndices: List[int]
    nonSignerStakeIndices: List[List[int]]


class BLSContractSigner:
    """BLS signer for contract interactions."""

    def __init__(self):
        self.keypairs = []

    def add_keypair(self, keypair):
        """Add a keypair to the signer."""
        self.keypairs.append(keypair)

    def add_random_keypair(self):
        """Add a random keypair for testing."""
        keypair = gen_random_bls_keys()
        self.add_keypair(keypair)
        return keypair

    def add_keypair_from_seed(self, seed: str):
        """Add a keypair from a seed string."""
        keypair = new_key_pair_from_string(seed)
        self.add_keypair(keypair)
        return keypair

    def sign_and_aggregate(self, message: bytes):
        """Sign message with all keypairs and return aggregated data."""
        if not self.keypairs:
            raise ValueError("No keypairs available")

        # Sign with all keypairs
        signatures = [kp.sign_message(message) for kp in self.keypairs]

        # Aggregate signatures using + operator
        aggregated_signature = signatures[0]
        for sig in signatures[1:]:
            aggregated_signature = aggregated_signature + sig

        # Convert back to Signature object for verification
        aggregated_signature = Signature.from_g1_point(aggregated_signature)

        # Aggregate G2 public keys
        aggregated_pubkey_g2 = self.keypairs[0].get_pub_g2()
        for kp in self.keypairs[1:]:
            aggregated_pubkey_g2 = aggregated_pubkey_g2 + kp.get_pub_g2()

        # Convert to contract format
        sigma = self._signature_to_g1_point(aggregated_signature)
        apk_g2 = self._pubkey_g2_to_g2_point(aggregated_pubkey_g2)
        individual_g1_points = [
            self._pubkey_g1_to_g1_point(kp.get_pub_g1()) for kp in self.keypairs
        ]

        return {
            "sigma": sigma,
            "apk_g2": apk_g2,
            "individual_pubkeys": individual_g1_points,
            "aggregated_signature": aggregated_signature,
            "aggregated_pubkey_g2": aggregated_pubkey_g2,
        }

    @staticmethod
    def _signature_to_g1_point(signature) -> G1Point:
        """Convert BLS signature to G1Point."""
        sig_str = signature.getStr().decode("utf-8").split()
        return G1Point(X=int(sig_str[1]), Y=int(sig_str[2]))

    @staticmethod
    def _pubkey_g1_to_g1_point(pubkey) -> G1Point:
        """Convert G1 public key to G1Point."""
        pubkey_str = pubkey.getStr().decode("utf-8").split()
        return G1Point(X=int(pubkey_str[1]), Y=int(pubkey_str[2]))

    @staticmethod
    def _pubkey_g2_to_g2_point(pubkey) -> G2Point:
        """Convert G2 public key to G2Point."""
        pubkey_str = pubkey.getStr().decode("utf-8").split()
        return G2Point(
            X=(int(pubkey_str[1]), int(pubkey_str[2])), Y=(int(pubkey_str[3]), int(pubkey_str[4]))
        )


class TestBLSContractSignatures:
    """Test BLS signature operations for contract interactions."""

    def test_basic_signature_aggregation(self):
        """Test basic signature aggregation for contract format."""
        signer = BLSContractSigner()
        signer.add_keypair_from_seed("seed1")
        signer.add_keypair_from_seed("seed2")

        message = b"Hello EigenLayer Contract!"
        result = signer.sign_and_aggregate(message)

        # Verify results
        assert isinstance(result["sigma"], G1Point)
        assert isinstance(result["apk_g2"], G2Point)
        assert len(result["individual_pubkeys"]) == 2
        assert result["sigma"].X != 0
        assert result["sigma"].Y != 0

    def test_multiple_operators_aggregation(self):
        """Test aggregation with multiple operators."""
        num_operators = 5
        signer = BLSContractSigner()

        # Add multiple keypairs
        for i in range(num_operators):
            signer.add_keypair_from_seed(f"operator_{i}")

        message = b"Multi-operator contract signature"
        result = signer.sign_and_aggregate(message)

        assert len(result["individual_pubkeys"]) == num_operators
        assert isinstance(result["sigma"], G1Point)
        assert isinstance(result["apk_g2"], G2Point)

    def test_random_keypairs_aggregation(self):
        """Test aggregation with random keypairs."""
        signer = BLSContractSigner()

        # Add random keypairs
        for _ in range(3):
            signer.add_random_keypair()

        message = b"Random keypair test"
        result = signer.sign_and_aggregate(message)

        assert len(result["individual_pubkeys"]) == 3
        assert result["sigma"].X > 0  # Ensure valid signature
        assert result["sigma"].Y > 0

    def test_contract_data_structures(self):
        """Test contract data structure creation and conversion."""
        signer = BLSContractSigner()
        signer.add_keypair_from_seed("test_seed")

        message = b"Contract structure test"
        result = signer.sign_and_aggregate(message)

        # Create NonSignerStakesAndSignature structure
        non_signer_data = NonSignerStakesAndSignature(
            nonSignerQuorumBitmapIndices=[],
            nonSignerPubkeys=[],
            quorumApks=result["individual_pubkeys"],
            apkG2=result["apk_g2"],
            sigma=result["sigma"],
            quorumApkIndices=[0],
            totalStakeIndices=[0],
            nonSignerStakeIndices=[[]],
        )

        # Verify structure
        assert len(non_signer_data.nonSignerPubkeys) == 0  # No non-signers
        assert len(non_signer_data.quorumApks) == 1
        assert isinstance(non_signer_data.apkG2, G2Point)
        assert isinstance(non_signer_data.sigma, G1Point)

    def test_g1_point_conversion(self):
        """Test G1Point data conversion."""
        point = G1Point(X=12345, Y=67890)
        tuple_format = point.to_tuple()

        assert tuple_format == (12345, 67890)
        assert isinstance(tuple_format[0], int)
        assert isinstance(tuple_format[1], int)

    def test_g2_point_conversion(self):
        """Test G2Point data conversion."""
        point = G2Point(X=(123, 456), Y=(789, 101112))
        tuple_format = point.to_tuple()

        expected = ([123, 456], [789, 101112])
        assert tuple_format == expected

    def test_signature_deterministic(self):
        """Test that signatures are deterministic with same seed."""
        message = b"Deterministic test"

        # Create two signers with same seeds
        signer1 = BLSContractSigner()
        signer1.add_keypair_from_seed("seed1")
        signer1.add_keypair_from_seed("seed2")

        signer2 = BLSContractSigner()
        signer2.add_keypair_from_seed("seed1")
        signer2.add_keypair_from_seed("seed2")

        result1 = signer1.sign_and_aggregate(message)
        result2 = signer2.sign_and_aggregate(message)

        # Should produce identical results
        assert result1["sigma"].X == result2["sigma"].X
        assert result1["sigma"].Y == result2["sigma"].Y
        assert result1["apk_g2"].X == result2["apk_g2"].X
        assert result1["apk_g2"].Y == result2["apk_g2"].Y

    def test_empty_signer_error(self):
        """Test error handling when no keypairs are added."""
        signer = BLSContractSigner()
        message = b"Test message"

        with pytest.raises(ValueError, match="No keypairs available"):
            signer.sign_and_aggregate(message)

    def test_single_operator_signature(self):
        """Test signature with single operator."""
        signer = BLSContractSigner()
        signer.add_keypair_from_seed("single_operator")

        message = b"Single operator test"
        result = signer.sign_and_aggregate(message)

        assert len(result["individual_pubkeys"]) == 1
        assert isinstance(result["sigma"], G1Point)
        assert isinstance(result["apk_g2"], G2Point)

    def test_contract_parameters_format(self):
        """Test formatting parameters for contract calls."""
        signer = BLSContractSigner()
        signer.add_keypair_from_seed("param_test")

        message = b"Parameter format test"
        result = signer.sign_and_aggregate(message)

        # Format as contract parameters
        sigma_tuple = result["sigma"].to_tuple()
        apk_g2_tuple = result["apk_g2"].to_tuple()
        pubkeys_tuples = [pk.to_tuple() for pk in result["individual_pubkeys"]]

        # Create contract parameters structure
        params: Tuple[
            List[int],
            List[Tuple[int, int]],
            List[Tuple[int, int]],
            Tuple[List[int], List[int]],
            Tuple[int, int],
            List[int],
            List[int],
            List[List[int]],
        ] = (
            [],  # nonSignerQuorumBitmapIndices
            [],  # nonSignerPubkeys
            pubkeys_tuples,  # quorumApks
            apk_g2_tuple,  # apkG2
            sigma_tuple,  # sigma
            [0],  # quorumApkIndices
            [0],  # totalStakeIndices
            [[]],  # nonSignerStakeIndices
        )

        assert len(params) == 8  # Expected number of parameters
        assert isinstance(params[4], tuple)  # sigma as tuple
        assert isinstance(params[3], tuple)  # apkG2 as tuple

    @patch("web3.Web3")
    def test_mock_contract_interaction(self, mock_web3):
        """Test mocked contract interaction."""
        # Setup mock
        mock_contract = Mock()
        mock_web3.return_value.eth.contract.return_value = mock_contract
        mock_web3.return_value.eth.block_number = 1000000

        # Mock successful contract call
        mock_contract.functions.checkSignatures.return_value.call.return_value = (
            ([100, 200], [150, 250]),  # QuorumStakeTotals
            b"\x12\x34\x56\x78" * 8,  # SignatoryRecordHash
        )

        signer = BLSContractSigner()
        signer.add_keypair_from_seed("contract_test")

        message = b"Mock contract test"
        result = signer.sign_and_aggregate(message)

        # Verify we can format data for contract call
        assert result["sigma"] is not None
        assert result["apk_g2"] is not None

    def test_aggregated_signature_verification(self):
        """Test that aggregated signatures verify correctly."""
        signer = BLSContractSigner()
        signer.add_keypair_from_seed("seed1")
        signer.add_keypair_from_seed("seed2")
        signer.add_keypair_from_seed("seed3")

        message = b"Aggregated signature verification test"
        result = signer.sign_and_aggregate(message)

        # Verify the aggregated signature works with aggregated public key
        assert result["aggregated_signature"].verify(result["aggregated_pubkey_g2"], message)

        # Verify individual signatures work
        for i, kp in enumerate(signer.keypairs):
            individual_sig = kp.sign_message(message)
            assert individual_sig.verify(kp.get_pub_g2(), message)

    def test_large_scale_aggregation(self):
        """Test aggregation with many operators."""
        num_operators = 20
        signer = BLSContractSigner()

        for i in range(num_operators):
            signer.add_random_keypair()

        message = b"Large scale aggregation test"
        result = signer.sign_and_aggregate(message)

        assert len(result["individual_pubkeys"]) == num_operators
        assert result["sigma"].X != 0
        assert result["sigma"].Y != 0

        # Verify the aggregated signature actually works
        assert result["aggregated_signature"].verify(result["aggregated_pubkey_g2"], message)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
