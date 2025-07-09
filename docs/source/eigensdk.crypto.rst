.. _eigensdk.crypto:

eigensdk.crypto
===============

This module provides classes and functions for handling BLS signatures, cryptographic key management, and various utility functions for elliptic curve operations using the BLS signature scheme.

Example Usage
-------------

.. code-block:: python

    >>> from eigensdk.crypto.bls.attestation import new_key_pair_from_string
    >>> # Generate a new key pair from a string seed
    >>> key_pair = new_key_pair_from_string("a1b2c3d4")
    >>> # Assume a simple message
    >>> message = b"Hello, world!"
    >>> # Sign the message with the private key
    >>> signature = key_pair.sign_message(message)
    >>> print("Signature JSON:", signature.to_json())
    Signature JSON: {'X': 10529196257730034571674059145519291271312341314564905285488980484390382467013, 'Y': 18927811237058023983585857108877009845959756493464435916975837710431732965093}
    >>> # Verification would typically need the public key in G2; simulate getting this
    >>> pub_g2 = key_pair.get_pub_g2()  # This would normally be known or retrieved independently
    >>> # Verify the signature against the message and the public key
    >>> is_valid = signature.verify(pub_g2, message)
    >>> print("Signature valid:", is_valid)
    Signature valid: True


This example demonstrates the complete lifecycle of a BLS signature within the `eigensdk.crypto.bls.attestation` module, from generating key pairs to signing messages and verifying those signatures. The `verify` method checks if the signature is valid given the original message and the signer's public key, ensuring the integrity and authenticity of the signed data.

eigensdk.crypto.bls.attestation
-------------------------------

.. automodule:: eigensdk.crypto.bls.attestation
    :members:
    :show-inheritance:
