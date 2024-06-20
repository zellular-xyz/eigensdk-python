.. _eigensdk.crypto:

eigensdk.crypto
===============

eigensdk.crypto.bls.attestation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides classes and functions for handling BLS signatures, cryptographic key management, and various utility functions for elliptic curve operations using the BLS signature scheme.

Classes and Functions
---------------------

.. py:class:: G1Point(x: int, y: int)

    Represents a point on the G1 curve. Provides basic arithmetic operations.

    :param x: The x-coordinate of the point.
    :param y: The y-coordinate of the point.

    .. py:method:: add(a: 'G1Point') -> 'G1Point'

        Adds another G1Point to this point and returns the result.

    .. py:method:: sub(a: 'G1Point') -> 'G1Point'

        Subtracts another G1Point from this point and returns the result.

    .. py:method:: verify_equivalence(a: 'G2Point') -> bool

        Verifies if a G1Point and a G2Point represent the same underlying discrete logarithm. Useful for signature verification.

.. py:function:: new_g1_point(x: int, y: int) -> G1Point

    Constructs a new G1Point.

    :param x: The x-coordinate of the point.
    :param y: The y-coordinate of the point.
    :return: A new G1Point object.

.. py:class:: G2Point(xa: int, xb: int, ya: int, yb: int)

    Represents a point on the G2 curve.

    :param xa: The first part of the x-coordinate of the point.
    :param xb: The second part of the x-coordinate of the point.
    :param ya: The first part of the y-coordinate of the point.
    :param yb: The second part of the y-coordinate of the point.

.. py:function:: new_g2_point(xa: int, xb: int, ya: int, yb: int) -> G2Point

    Constructs a new G2Point.

    :param xa: The first part of the x-coordinate of the point.
    :param xb: The second part of the x-coordinate of the point.
    :param ya: The first part of the y-coordinate of the point.
    :param yb: The second part of the y-coordinate of the point.
    :return: A new G2Point object.

.. py:class:: Signature(G1Point)

    A special type of G1Point specifically used for signatures.

    .. py:staticmethod:: from_g1_point(p: G1Point) -> 'Signature'

        Constructs a Signature from a G1Point.

.. py:class:: PrivateKey(secret: bytes = None)

    Represents a BLS private key.

    :param secret: A byte array to initialize the private key.

    .. py:method:: get_str() -> str

        Returns the private key as a hexadecimal string.

.. py:class:: KeyPair(priv_key: PrivateKey = None)

    Represents a BLS key pair, including both private and public keys.

    :param priv_key: A PrivateKey object to initialize the KeyPair.

    .. py:method:: sign_message(msg_bytes: bytes) -> Signature

        Signs a message using the private key of the key pair.

    .. py:staticmethod:: from_string(sk: str, base=16) -> 'KeyPair'

        Constructs a KeyPair from a private key string.

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
