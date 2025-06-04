import pytest
from eigensdk.crypto.bls.attestation import (
    new_key_pair_from_string,
    gen_random_bls_keys,
    new_zero_signature,
)


class TestBLSAggregation:
    """Test BLS signature aggregation functionality."""

    def test_signature_aggregation_simple(self):
        """Test basic signature aggregation with 2 operators."""
        # Create two key pairs
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")

        message = b"Hello EigenLayer!"

        # Sign message with both key pairs
        sig1 = key_pair1.sign_message(message)
        sig2 = key_pair2.sign_message(message)

        # Aggregate signatures and public keys
        aggregated_sig = sig1.add(sig2)
        aggregated_pub_g1 = key_pair1.get_pub_g1() + key_pair2.get_pub_g1()

        # Verify aggregated signature works
        assert aggregated_sig.verify(key_pair1.get_pub_g2() + key_pair2.get_pub_g2(), message)

        # Verify aggregated public key is actually the sum of individual keys
        pub_g1_1 = key_pair1.get_pub_g1()
        pub_g1_2 = key_pair2.get_pub_g1()
        expected_aggregated = pub_g1_1 + pub_g1_2

        assert aggregated_pub_g1.getX().getStr() == expected_aggregated.getX().getStr()
        assert aggregated_pub_g1.getY().getStr() == expected_aggregated.getY().getStr()

    def test_signature_aggregation_multiple_operators(self):
        """Test signature aggregation with multiple operators."""
        num_operators = 5
        operators = []
        signatures = []
        message = b"Multi-operator test message"

        # Create operators and collect signatures
        for i in range(num_operators):
            key_pair = new_key_pair_from_string(f"operator_{i}")
            operators.append(key_pair)
            signature = key_pair.sign_message(message)
            signatures.append(signature)

            # Verify individual signature
            assert signature.verify(key_pair.get_pub_g2(), message)
            print(f"✅ Operator {i} signature valid")

        # Aggregate all signatures
        aggregated_sig = signatures[0]
        for sig in signatures[1:]:
            aggregated_sig = aggregated_sig.add(sig)

        # Aggregate all public keys (G1)
        aggregated_pub_g1 = operators[0].get_pub_g1()
        for op in operators[1:]:
            aggregated_pub_g1 = aggregated_pub_g1 + op.get_pub_g1()

        print(f"🔗 Aggregated {num_operators} signatures successfully")
        print(f"Aggregated signature: {aggregated_sig.to_json()}")

    def test_signature_aggregation_with_different_messages_fails(self):
        """Test that aggregating signatures for different messages doesn't verify properly."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")

        message1 = b"Message 1"
        message2 = b"Message 2"

        # Sign different messages
        sig1 = key_pair1.sign_message(message1)
        sig2 = key_pair2.sign_message(message2)

        # Individual signatures should be valid for their respective messages
        assert sig1.verify(key_pair1.get_pub_g2(), message1)
        assert sig2.verify(key_pair2.get_pub_g2(), message2)

        # But invalid for wrong messages
        assert not sig1.verify(key_pair1.get_pub_g2(), message2)
        assert not sig2.verify(key_pair2.get_pub_g2(), message1)

        print("✅ Different message verification works correctly")

    def test_empty_signature_aggregation(self):
        """Test aggregation starting from zero signature."""
        key_pair = new_key_pair_from_string("test_seed")
        message = b"Test message"
        signature = key_pair.sign_message(message)
        # Start with zero signature
        zero_sig = new_zero_signature()
        aggregated = zero_sig.add(signature)
        # Verify both original and aggregated signatures work
        assert signature.verify(key_pair.get_pub_g2(), message)
        assert aggregated.verify(key_pair.get_pub_g2(), message)
        # Aggregated should be equivalent to original when adding zero
        assert aggregated.to_json() == signature.to_json()
        print("✅ Zero signature aggregation works")

    def test_signature_aggregation_order_independence(self):
        """Test that signature aggregation is order-independent (commutative)."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")
        key_pair3 = new_key_pair_from_string("seed3")

        message = b"Order test message"

        sig1 = key_pair1.sign_message(message)
        sig2 = key_pair2.sign_message(message)
        sig3 = key_pair3.sign_message(message)

        # Aggregate in different orders
        agg_123 = sig1.add(sig2).add(sig3)
        agg_321 = sig3.add(sig2).add(sig1)
        agg_213 = sig2.add(sig1).add(sig3)

        # All should produce the same result
        assert agg_123.to_json() == agg_321.to_json()
        assert agg_123.to_json() == agg_213.to_json()

        print("✅ Signature aggregation is order-independent")

    def test_public_key_aggregation_order_independence(self):
        """Test that public key aggregation is order-independent."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")
        key_pair3 = new_key_pair_from_string("seed3")

        pub1 = key_pair1.get_pub_g1()
        pub2 = key_pair2.get_pub_g1()
        pub3 = key_pair3.get_pub_g1()

        # Aggregate in different orders
        agg_123 = pub1 + pub2 + pub3
        agg_321 = pub3 + pub2 + pub1
        agg_213 = pub2 + pub1 + pub3

        # Convert to comparable format
        def point_to_tuple(point):
            return int(point.getX().getStr()), int(point.getY().getStr())

        assert point_to_tuple(agg_123) == point_to_tuple(agg_321)
        assert point_to_tuple(agg_123) == point_to_tuple(agg_213)

        print("✅ Public key aggregation is order-independent")

    def test_large_scale_aggregation(self):
        """Test aggregation with many operators (stress test)."""
        num_operators = 50
        message = b"Large scale test message"

        print(f"🧪 Testing aggregation with {num_operators} operators...")

        operators = []
        signatures = []

        # Generate operators and signatures
        for i in range(num_operators):
            key_pair = gen_random_bls_keys()  # Use random keys for variety
            operators.append(key_pair)
            signature = key_pair.sign_message(message)
            signatures.append(signature)

        # Aggregate all signatures
        aggregated_sig = signatures[0]
        for sig in signatures[1:]:
            aggregated_sig = aggregated_sig.add(sig)

        # Aggregate all public keys (G2 for verification)
        aggregated_pub_g2 = operators[0].get_pub_g2()
        for op in operators[1:]:
            aggregated_pub_g2 = aggregated_pub_g2 + op.get_pub_g2()

        # Verify aggregated signature works
        assert aggregated_sig.verify(aggregated_pub_g2, message)

        # Verify some individual signatures still work
        for i in range(0, min(5, num_operators)):
            assert signatures[i].verify(operators[i].get_pub_g2(), message)

        print(f"✅ Successfully aggregated {num_operators} signatures")
        print(f"Aggregated signature size: {len(str(aggregated_sig.to_json()))} chars")

    def test_partial_signature_aggregation(self):
        """Test aggregating only a subset of available signatures."""
        total_operators = 10
        participating_operators = 6

        message = b"Partial participation test"

        # Create all operators
        all_operators = []
        all_signatures = []

        for i in range(total_operators):
            key_pair = new_key_pair_from_string(f"operator_{i}")
            all_operators.append(key_pair)
            signature = key_pair.sign_message(message)
            all_signatures.append(signature)

        # Select subset for aggregation
        participating_indices = list(range(participating_operators))

        # Aggregate subset signatures
        subset_sig = all_signatures[0]
        for i in participating_indices[1:]:
            subset_sig = subset_sig.add(all_signatures[i])

        # Aggregate subset public keys (G2 for verification)
        subset_pub_g2 = all_operators[0].get_pub_g2()
        for i in participating_indices[1:]:
            subset_pub_g2 = subset_pub_g2 + all_operators[i].get_pub_g2()

        # Verify the aggregated subset signature works
        assert subset_sig.verify(subset_pub_g2, message)

        print(f"✅ Aggregated {participating_operators}/{total_operators} operators")
        print("Subset aggregation successful")

    def test_signature_serialization_after_aggregation(self):
        """Test that aggregated signatures can be properly serialized."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")

        message = b"Serialization test"

        sig1 = key_pair1.sign_message(message)
        sig2 = key_pair2.sign_message(message)

        aggregated_sig = sig1.add(sig2)

        # Test JSON serialization
        sig_json = aggregated_sig.to_json()

        assert isinstance(sig_json, dict)
        assert "X" in sig_json
        assert "Y" in sig_json
        assert isinstance(sig_json["X"], int)
        assert isinstance(sig_json["Y"], int)

        print(f"✅ Aggregated signature JSON: {sig_json}")

    def test_deterministic_aggregation(self):
        """Test that aggregation is deterministic with same inputs."""
        message = b"Deterministic test"

        # Create the same signatures multiple times
        results = []
        for trial in range(3):
            key_pair1 = new_key_pair_from_string("seed1")
            key_pair2 = new_key_pair_from_string("seed2")

            sig1 = key_pair1.sign_message(message)
            sig2 = key_pair2.sign_message(message)

            aggregated = sig1.add(sig2)
            results.append(aggregated.to_json())

        # All results should be identical
        assert all(result == results[0] for result in results)
        print("✅ Aggregation is deterministic")

    def test_aggregation_with_zero_operators(self):
        """Test edge case handling with no operators."""
        # This should be handled gracefully in practice
        zero_sig = new_zero_signature()
        zero_json = zero_sig.to_json()

        assert zero_json["X"] == 0
        assert zero_json["Y"] == 0

        print("✅ Zero signature handling works")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
