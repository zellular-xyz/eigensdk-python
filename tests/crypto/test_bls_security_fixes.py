import pytest
from eigensdk.crypto.bls.attestation import (
    KeyPair,
    G1Point,
    G2Point,
    new_key_pair_from_string,
    gen_random_bls_keys,
    g1_to_tuple,
    g2_to_tuple,
)
from eigensdk.crypto.bn256 import utils as bn256Utils


class TestBLSSecurityFixes:
    """Test suite for BLS security fixes and improvements."""

    def test_consistent_key_derivation(self):
        """Test that key derivation is now consistent and collision-resistant."""
        # Same string should always produce same key
        key1 = new_key_pair_from_string("test_seed")
        key2 = new_key_pair_from_string("test_seed")
        
        assert key1.get_pub_g1().getX().getStr() == key2.get_pub_g1().getX().getStr()
        assert key1.get_pub_g1().getY().getStr() == key2.get_pub_g1().getY().getStr()
        
        # Different strings should produce different keys
        key3 = new_key_pair_from_string("different_seed")
        assert key1.get_pub_g1().getX().getStr() != key3.get_pub_g1().getX().getStr()

    def test_key_derivation_collision_resistance(self):
        """Test that the old collision-prone key derivation is fixed."""
        # These inputs previously could cause collisions due to different encoding paths
        inputs = [
            "123",  # Small number
            "0x123",  # Hex format
            "456789" * 20,  # Very long string
            "999999999999999999999999999999999999999999999999999999999999999999999999999999",  # Large number
        ]
        
        keys = []
        for input_str in inputs:
            key = new_key_pair_from_string(input_str)
            keys.append(g1_to_tuple(key.get_pub_g1()))
        
        # All keys should be different
        assert len(set(keys)) == len(keys), "Key collision detected!"

    def test_domain_separation_in_signatures(self):
        """Test that domain separation works in signatures."""
        key_pair = new_key_pair_from_string("test_key")
        message = b"test message"
        
        # Domain separated signatures should be different
        domain1 = b"DOMAIN_1"
        domain2 = b"DOMAIN_2"
        
        sig1 = key_pair.sign_message(message, domain1)
        sig2 = key_pair.sign_message(message, domain2)
        
        # Signatures should be different
        assert sig1.to_json() != sig2.to_json()
        
        # Verify signatures with correct domains
        assert sig1.verify(key_pair.get_pub_g2(), message, domain1)
        assert sig2.verify(key_pair.get_pub_g2(), message, domain2)
        
        # Verify signatures fail with wrong domains
        assert not sig1.verify(key_pair.get_pub_g2(), message, domain2)
        assert not sig2.verify(key_pair.get_pub_g2(), message, domain1)

    def test_secure_hash_to_curve(self):
        """Test that the new hash-to-curve implementation is deterministic and secure."""
        message1 = b"test message 1"
        message2 = b"test message 2"
        domain = b"TEST_DOMAIN"
        
        # Same message should map to same curve point
        point1a = bn256Utils.map_to_curve(message1, domain)
        point1b = bn256Utils.map_to_curve(message1, domain)
        
        assert g1_to_tuple(point1a) == g1_to_tuple(point1b)
        
        # Different messages should map to different points
        point2 = bn256Utils.map_to_curve(message2, domain)
        assert g1_to_tuple(point1a) != g1_to_tuple(point2)

    def test_static_methods_fixed(self):
        """Test that static methods are properly decorated."""
        # These should work without instances
        g1_gen = bn256Utils.get_g1_generator()
        g1_point = G1Point.from_G1(g1_gen)
        
        g2_gen = bn256Utils.get_g2_generator()
        g2_point = G2Point.from_G2(g2_gen)
        
        assert isinstance(g1_point, G1Point)
        assert isinstance(g2_point, G2Point)

    def test_typo_fixes(self):
        """Test that function names are correctly spelled."""
        # These functions should exist with correct spelling
        key_pair = gen_random_bls_keys()
        
        g1_tuple = g1_to_tuple(key_pair.get_pub_g1())
        g2_tuple = g2_to_tuple(key_pair.get_pub_g2())
        
        assert isinstance(g1_tuple, tuple)
        assert len(g1_tuple) == 2
        assert isinstance(g2_tuple, tuple)
        assert len(g2_tuple) == 2

    def test_consistent_public_key_computation(self):
        """Test that public key computation is consistent between methods."""
        key_pair = gen_random_bls_keys()
        
        # These should return the same values
        pub_g1_from_getter = key_pair.get_pub_g1()
        pub_g2_from_getter = key_pair.get_pub_g2()
        
        # Compare with internal cached values (normalized)
        pub_g1_cached = G1Point.from_G1(key_pair.pub_g1)
        pub_g2_cached = G2Point.from_G2(key_pair.pub_g2)
        
        assert g1_to_tuple(pub_g1_from_getter) == g1_to_tuple(pub_g1_cached)
        assert g2_to_tuple(pub_g2_from_getter) == g2_to_tuple(pub_g2_cached)

    def test_private_key_validation(self):
        """Test that private key validation works."""
        from eigensdk.crypto.bls.attestation import PrivateKey
        
        # Valid 32-byte key should work
        valid_key = b"\x01" * 32
        priv_key = PrivateKey(valid_key)
        assert priv_key is not None
        
        # Invalid length should raise error
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            PrivateKey(b"\x01" * 16)  # Too short
        
        with pytest.raises(ValueError, match="Private key must be exactly 32 bytes"):
            PrivateKey(b"\x01" * 64)  # Too long

    def test_secure_random_generation(self):
        """Test that random key generation uses secure randomness."""
        # Generate multiple keys and ensure they're different
        keys = []
        for _ in range(10):
            key = gen_random_bls_keys()
            keys.append(g1_to_tuple(key.get_pub_g1()))
        
        # All keys should be different
        assert len(set(keys)) == len(keys), "Non-random key generation detected!"

    def test_keystore_bls_marking(self):
        """Test that BLS keys are properly marked in keystore."""
        import tempfile
        import os
        
        key_pair = new_key_pair_from_string("test_keystore")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            # Save keystore
            key_pair.save_to_file(temp_path, "test_password")
            
            # Read and verify
            loaded_key = KeyPair.read_from_file(temp_path, "test_password")
            
            # Keys should be identical
            assert g1_to_tuple(key_pair.get_pub_g1()) == g1_to_tuple(loaded_key.get_pub_g1())
            
            # Verify keystore contains BLS marker
            import json
            with open(temp_path, 'r') as f:
                keystore_data = json.load(f)
            
            assert keystore_data.get("keyType") == "BLS"
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_signature_verification_security(self):
        """Test comprehensive signature verification scenarios."""
        key_pair1 = new_key_pair_from_string("signer1")
        key_pair2 = new_key_pair_from_string("signer2")
        
        message = b"important message"
        domain = b"SECURE_DOMAIN"
        
        # Sign with key1
        signature = key_pair1.sign_message(message, domain)
        
        # Should verify with correct key
        assert signature.verify(key_pair1.get_pub_g2(), message, domain)
        
        # Should fail with wrong key
        assert not signature.verify(key_pair2.get_pub_g2(), message, domain)
        
        # Should fail with wrong message
        assert not signature.verify(key_pair1.get_pub_g2(), b"wrong message", domain)
        
        # Should fail with wrong domain
        assert not signature.verify(key_pair1.get_pub_g2(), message, b"WRONG_DOMAIN")

    def test_no_variable_shadowing(self):
        """Test that variable shadowing issues are fixed."""
        # This test ensures the verify_sig function works correctly
        # without variable shadowing issues
        key_pair = new_key_pair_from_string("no_shadow_test")
        message = b"test message"
        
        signature = key_pair.sign_message(message)
        
        # This should work without any G1/G2 type shadowing issues
        assert signature.verify(key_pair.get_pub_g2(), message)
        
        # Test the discrete log equality check too
        assert key_pair.get_pub_g1().verify_equivalence(key_pair.get_pub_g2())