from eigensdk.crypto.bls.attestation import (
    new_key_pair_from_string,
    new_zero_signature,
    g1_to_tuple,
    g2_to_tuple,
)


class TestBLSAggregation:
    """Comprehensive test suite for BLS signature and public key aggregation."""

    def test_basic_signature_aggregation(self):
        """Test basic signature aggregation with 2 operators."""
        # Create two key pairs
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")

        message = b"Hello EigenLayer!"

        # Sign message with both key pairs
        sig1 = key_pair1.sign_message(message)
        sig2 = key_pair2.sign_message(message)

        # Aggregate signatures
        aggregated_sig = sig1.add(sig2)

        # Aggregate public keys
        aggregated_pub_g1 = key_pair1.get_pub_g1() + key_pair2.get_pub_g1()
        aggregated_pub_g2 = key_pair1.get_pub_g2() + key_pair2.get_pub_g2()

        # Verify aggregated signature works
        assert aggregated_sig.verify(aggregated_pub_g2, message)

        # Verify aggregated public key is actually the sum of individual keys
        pub_g1_1 = key_pair1.get_pub_g1()
        pub_g1_2 = key_pair2.get_pub_g1()
        expected_aggregated = pub_g1_1 + pub_g1_2

        assert g1_to_tuple(aggregated_pub_g1) == g1_to_tuple(expected_aggregated)

    def test_multiple_operators_aggregation(self):
        """Test aggregation with multiple operators (5 operators)."""
        num_operators = 5
        key_pairs = []
        signatures = []

        message = b"Multi-operator aggregation test"

        # Generate key pairs and signatures
        for i in range(num_operators):
            key_pair = new_key_pair_from_string(f"operator_{i}")
            key_pairs.append(key_pair)
            signatures.append(key_pair.sign_message(message))

        # Aggregate all signatures
        aggregated_sig = signatures[0]
        for sig in signatures[1:]:
            aggregated_sig = aggregated_sig.add(sig)

        # Aggregate all G1 public keys
        aggregated_pub_g1 = key_pairs[0].get_pub_g1()
        for kp in key_pairs[1:]:
            aggregated_pub_g1 = aggregated_pub_g1 + kp.get_pub_g1()

        # Aggregate all G2 public keys
        aggregated_pub_g2 = key_pairs[0].get_pub_g2()
        for kp in key_pairs[1:]:
            aggregated_pub_g2 = aggregated_pub_g2 + kp.get_pub_g2()

        # Verify aggregated signature
        assert aggregated_sig.verify(aggregated_pub_g2, message)

        # Test that individual signatures still work
        for i, (kp, sig) in enumerate(zip(key_pairs, signatures)):
            assert sig.verify(kp.get_pub_g2(), message), f"Individual signature {i} failed"

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

    def test_public_key_aggregation_order_independence(self):
        """Test that public key aggregation is order-independent."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")
        key_pair3 = new_key_pair_from_string("seed3")

        pub1_g1 = key_pair1.get_pub_g1()
        pub2_g1 = key_pair2.get_pub_g1()
        pub3_g1 = key_pair3.get_pub_g1()

        pub1_g2 = key_pair1.get_pub_g2()
        pub2_g2 = key_pair2.get_pub_g2()
        pub3_g2 = key_pair3.get_pub_g2()

        # Aggregate G1 keys in different orders
        agg_g1_123 = pub1_g1 + pub2_g1 + pub3_g1
        agg_g1_321 = pub3_g1 + pub2_g1 + pub1_g1
        agg_g1_213 = pub2_g1 + pub1_g1 + pub3_g1

        # Aggregate G2 keys in different orders
        agg_g2_123 = pub1_g2 + pub2_g2 + pub3_g2
        agg_g2_321 = pub3_g2 + pub2_g2 + pub1_g2
        agg_g2_213 = pub2_g2 + pub1_g2 + pub3_g2

        # All G1 aggregations should be equal
        assert g1_to_tuple(agg_g1_123) == g1_to_tuple(agg_g1_321)
        assert g1_to_tuple(agg_g1_123) == g1_to_tuple(agg_g1_213)

        # All G2 aggregations should be equal
        assert g2_to_tuple(agg_g2_123) == g2_to_tuple(agg_g2_321)
        assert g2_to_tuple(agg_g2_123) == g2_to_tuple(agg_g2_213)

    def test_single_signature_aggregation(self):
        """Test aggregation with a single signature (edge case)."""
        key_pair = new_key_pair_from_string("single_signer")
        message = b"Single signature test"

        signature = key_pair.sign_message(message)

        # Aggregating a single signature should be the signature itself
        aggregated_sig = signature.add(new_zero_signature())

        # Both should verify successfully
        assert signature.verify(key_pair.get_pub_g2(), message)
        assert aggregated_sig.verify(key_pair.get_pub_g2(), message)

    def test_empty_signature_handling(self):
        """Test handling of zero/empty signatures in aggregation."""
        key_pair = new_key_pair_from_string("zero_test")
        message = b"Zero signature test"

        signature = key_pair.sign_message(message)
        zero_sig = new_zero_signature()

        # Adding zero signature should not change the result
        aggregated = signature.add(zero_sig)

        # Original signature should still verify
        assert signature.verify(key_pair.get_pub_g2(), message)
        # Aggregated with zero should also verify
        assert aggregated.verify(key_pair.get_pub_g2(), message)

    def test_different_messages_same_signers(self):
        """Test aggregation fails when signers sign different messages."""
        key_pair1 = new_key_pair_from_string("signer1")
        key_pair2 = new_key_pair_from_string("signer2")

        message1 = b"Message one"
        message2 = b"Message two"

        # Sign different messages
        sig1 = key_pair1.sign_message(message1)
        sig2 = key_pair2.sign_message(message2)

        # Aggregate signatures
        aggregated_sig = sig1.add(sig2)
        aggregated_pub_g2 = key_pair1.get_pub_g2() + key_pair2.get_pub_g2()

        # Verification should fail for both original messages
        assert not aggregated_sig.verify(aggregated_pub_g2, message1)
        assert not aggregated_sig.verify(aggregated_pub_g2, message2)

    def test_large_scale_aggregation(self):
        """Test aggregation with many operators (stress test)."""
        num_operators = 20
        key_pairs = []
        signatures = []

        message = b"Large scale aggregation test"

        # Generate many key pairs and signatures
        for i in range(num_operators):
            key_pair = new_key_pair_from_string(f"large_scale_operator_{i}")
            key_pairs.append(key_pair)
            signatures.append(key_pair.sign_message(message))

        # Aggregate all signatures
        aggregated_sig = signatures[0]
        for sig in signatures[1:]:
            aggregated_sig = aggregated_sig.add(sig)

        # Aggregate all public keys
        aggregated_pub_g2 = key_pairs[0].get_pub_g2()
        for kp in key_pairs[1:]:
            aggregated_pub_g2 = aggregated_pub_g2 + kp.get_pub_g2()

        # Verify aggregated signature
        assert aggregated_sig.verify(aggregated_pub_g2, message)

    def test_incremental_aggregation(self):
        """Test incremental aggregation (adding operators one by one)."""
        message = b"Incremental aggregation test"

        # Start with first operator
        key_pair1 = new_key_pair_from_string("incremental_1")
        aggregated_sig = key_pair1.sign_message(message)
        aggregated_pub_g2 = key_pair1.get_pub_g2()

        # Verify single signature
        assert aggregated_sig.verify(aggregated_pub_g2, message)

        # Add second operator
        key_pair2 = new_key_pair_from_string("incremental_2")
        sig2 = key_pair2.sign_message(message)
        aggregated_sig = aggregated_sig.add(sig2)
        aggregated_pub_g2 = aggregated_pub_g2 + key_pair2.get_pub_g2()

        # Verify with two signatures
        assert aggregated_sig.verify(aggregated_pub_g2, message)

        # Add third operator
        key_pair3 = new_key_pair_from_string("incremental_3")
        sig3 = key_pair3.sign_message(message)
        aggregated_sig = aggregated_sig.add(sig3)
        aggregated_pub_g2 = aggregated_pub_g2 + key_pair3.get_pub_g2()

        # Verify with three signatures
        assert aggregated_sig.verify(aggregated_pub_g2, message)

    def test_deterministic_aggregation(self):
        """Test that aggregation is deterministic with same inputs."""
        key_pairs = [
            new_key_pair_from_string("det_seed_1"),
            new_key_pair_from_string("det_seed_2"),
            new_key_pair_from_string("det_seed_3"),
        ]

        message = b"Deterministic test message"

        # Perform aggregation twice
        def aggregate_signatures():
            sigs = [kp.sign_message(message) for kp in key_pairs]
            agg_sig = sigs[0]
            for sig in sigs[1:]:
                agg_sig = agg_sig.add(sig)
            return agg_sig

        agg1 = aggregate_signatures()
        agg2 = aggregate_signatures()

        # Results should be identical
        assert agg1.to_json() == agg2.to_json()

    def test_partial_aggregation_subsets(self):
        """Test aggregation with different subsets of operators."""
        key_pairs = [new_key_pair_from_string(f"subset_operator_{i}") for i in range(5)]

        message = b"Subset aggregation test"
        signatures = [kp.sign_message(message) for kp in key_pairs]

        # Test different subsets
        subsets = [
            [0, 1],  # First two
            [2, 3, 4],  # Last three
            [0, 2, 4],  # Every other
            [1, 3],  # Middle two
        ]

        for subset_indices in subsets:
            # Aggregate subset signatures
            subset_sigs = [signatures[i] for i in subset_indices]
            subset_keys = [key_pairs[i] for i in subset_indices]

            agg_sig = subset_sigs[0]
            for sig in subset_sigs[1:]:
                agg_sig = agg_sig.add(sig)

            # Aggregate subset public keys
            agg_pub_g2 = subset_keys[0].get_pub_g2()
            for kp in subset_keys[1:]:
                agg_pub_g2 = agg_pub_g2 + kp.get_pub_g2()

            # Verify subset aggregation
            assert agg_sig.verify(agg_pub_g2, message), f"Subset {subset_indices} failed"

    def test_domain_separated_aggregation(self):
        """Test aggregation with domain separation."""
        key_pair1 = new_key_pair_from_string("domain_sep_1")
        key_pair2 = new_key_pair_from_string("domain_sep_2")

        message = b"Domain separated message"
        domain = b"TEST_AGGREGATION_DOMAIN"

        # Sign with domain separation
        sig1 = key_pair1.sign_message(message, domain)
        sig2 = key_pair2.sign_message(message, domain)

        # Aggregate signatures and keys
        aggregated_sig = sig1.add(sig2)
        aggregated_pub_g2 = key_pair1.get_pub_g2() + key_pair2.get_pub_g2()

        # Verify with domain separation
        assert aggregated_sig.verify(aggregated_pub_g2, message, domain)

        # Should fail without domain separation
        assert not aggregated_sig.verify(aggregated_pub_g2, message)

    def test_aggregation_associativity(self):
        """Test that aggregation is associative: (a + b) + c = a + (b + c)."""
        key_pair1 = new_key_pair_from_string("assoc_1")
        key_pair2 = new_key_pair_from_string("assoc_2")
        key_pair3 = new_key_pair_from_string("assoc_3")

        message = b"Associativity test"

        sig1 = key_pair1.sign_message(message)
        sig2 = key_pair2.sign_message(message)
        sig3 = key_pair3.sign_message(message)

        # Test (sig1 + sig2) + sig3
        left_assoc = sig1.add(sig2).add(sig3)

        # Test sig1 + (sig2 + sig3)
        right_assoc = sig1.add(sig2.add(sig3))

        # Results should be the same
        assert left_assoc.to_json() == right_assoc.to_json()

    def test_signature_aggregation_json_consistency(self):
        """Test that aggregated signatures have consistent JSON representation."""
        key_pairs = [
            new_key_pair_from_string("json_test_1"),
            new_key_pair_from_string("json_test_2"),
        ]

        message = b"JSON consistency test"
        signatures = [kp.sign_message(message) for kp in key_pairs]

        # Aggregate signatures
        aggregated = signatures[0].add(signatures[1])

        # Check JSON format
        json_data = aggregated.to_json()
        assert isinstance(json_data, dict)
        assert "X" in json_data
        assert "Y" in json_data
        assert isinstance(json_data["X"], int)
        assert isinstance(json_data["Y"], int)
        assert json_data["X"] != 0  # Should not be zero point
        assert json_data["Y"] != 0
