from eigensdk.crypto.bls.attestation import new_key_pair_from_string, G1Point, g1_to_tuple


class TestBLSAttestation:
    def test_key_pair_generation_from_string(self):
        """Test that key pairs can be generated from string seeds."""
        seed = "a1b2c3d4"
        key_pair = new_key_pair_from_string(seed)

        assert key_pair is not None
        assert hasattr(key_pair, "sign_message")
        assert hasattr(key_pair, "get_pub_g2")

    def test_deterministic_key_generation(self):
        """Test that the same seed produces the same key pair."""
        seed = "test_seed_123"
        key_pair1 = new_key_pair_from_string(seed)
        key_pair2 = new_key_pair_from_string(seed)

        # Both key pairs should generate the same public key
        pub_g2_1 = key_pair1.get_pub_g2().getStr()
        pub_g2_2 = key_pair2.get_pub_g2().getStr()
        assert pub_g2_1 == pub_g2_2

    def test_message_signing_and_verification(self):
        """Test basic message signing and verification workflow."""
        key_pair = new_key_pair_from_string("a1b2c3d4")
        message = b"Hello, world!"

        # Sign the message
        signature = key_pair.sign_message(message)

        assert signature is not None
        assert hasattr(signature, "to_json")
        assert hasattr(signature, "verify")

        # Get public key for verification
        pub_g2 = key_pair.get_pub_g2()

        # Verify the signature
        is_valid = signature.verify(pub_g2, message)
        assert is_valid is True

    def test_signature_json_format(self):
        """Test that signature JSON contains expected fields."""
        key_pair = new_key_pair_from_string("a1b2c3d4")
        message = b"Hello, world!"
        signature = key_pair.sign_message(message)

        signature_json = signature.to_json()

        assert isinstance(signature_json, dict)
        assert "X" in signature_json
        assert "Y" in signature_json
        assert isinstance(signature_json["X"], int)
        assert isinstance(signature_json["Y"], int)

    def test_signature_verification_with_wrong_message(self):
        """Test that signature verification fails with wrong message."""
        key_pair = new_key_pair_from_string("a1b2c3d4")
        original_message = b"Hello, world!"
        wrong_message = b"Hello, universe!"

        # Sign original message
        signature = key_pair.sign_message(original_message)
        pub_g2 = key_pair.get_pub_g2()

        # Verify with wrong message should fail
        is_valid = signature.verify(pub_g2, wrong_message)
        assert is_valid is False

    def test_signature_verification_with_wrong_public_key(self):
        """Test that signature verification fails with wrong public key."""
        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")
        message = b"Hello, world!"

        # Sign with first key pair
        signature = key_pair1.sign_message(message)

        # Try to verify with second key pair's public key
        wrong_pub_g2 = key_pair2.get_pub_g2()
        is_valid = signature.verify(wrong_pub_g2, message)
        assert is_valid is False

    def test_different_seeds_produce_different_signatures(self):
        """Test that different seeds produce different signatures for same message."""
        message = b"Hello, world!"

        key_pair1 = new_key_pair_from_string("seed1")
        key_pair2 = new_key_pair_from_string("seed2")

        signature1 = key_pair1.sign_message(message)
        signature2 = key_pair2.sign_message(message)

        # Signatures should be different
        assert signature1.to_json() != signature2.to_json()

    def test_empty_string_seed(self):
        """Test key pair generation with empty string seed."""
        key_pair = new_key_pair_from_string("")
        message = b"test message"

        signature = key_pair.sign_message(message)
        pub_g2 = key_pair.get_pub_g2()
        is_valid = signature.verify(pub_g2, message)

        assert is_valid is True

    def test_unicode_seed(self):
        """Test key pair generation with unicode characters in seed."""
        unicode_seed = "测试种子🔑"
        key_pair = new_key_pair_from_string(unicode_seed)
        message = b"test message"

        signature = key_pair.sign_message(message)
        pub_g2 = key_pair.get_pub_g2()
        is_valid = signature.verify(pub_g2, message)

        assert is_valid is True

    def test_long_seed(self):
        """Test key pair generation with a very long seed."""
        long_seed = "a" * 1000
        key_pair = new_key_pair_from_string(long_seed)
        message = b"test message"

        signature = key_pair.sign_message(message)
        pub_g2 = key_pair.get_pub_g2()
        is_valid = signature.verify(pub_g2, message)

        assert is_valid is True

    def test_g1_point_operations_and_conversion(self):
        """Test G1Point creation, addition, and conversion to tuple and string."""
        # Create a G1Point with specific coordinates
        a = G1Point(
            21242924253830336613447550815376789474630333403745828964344218064739394108833,
            14195402005158492706370388286202610633446140045109801404942361137198473695108,
        )

        # Test point addition (doubling)
        doubled_point = a + a

        # Test conversion to tuple
        tuple_result = g1_to_tuple(doubled_point)
        assert isinstance(tuple_result, tuple)
        assert len(tuple_result) == 2
        assert isinstance(tuple_result[0], int)
        assert isinstance(tuple_result[1], int)

        # Test string representation (returns bytes)
        str_result = doubled_point.getStr()
        assert isinstance(str_result, bytes)
        assert len(str_result) > 0

        # Verify that tuple and string represent the same point data
        # Convert bytes to string for comparison
        str_decoded = str_result.decode("utf-8")
        assert str(tuple_result[0]) in str_decoded or str(tuple_result[1]) in str_decoded
