import base64
import binascii
import json
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ecdsa import SigningKey, SECP256k1
from eth_utils import to_checksum_address, keccak


def write_key_from_hex(path, private_key_hex, password):
    private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    return write_key(path, private_key, password)


def write_key(path, private_key, password):
    key_id = str(uuid.uuid4())
    public_key = private_key.get_verifying_key().to_string()
    address = to_checksum_address(keccak(public_key)[-20:].hex())

    key_data = {
        "id": key_id,
        "address": address,
        "private_key": base64.b64encode(encrypt_key(private_key.to_string(), password)).decode(),
    }

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(key_data, f)

    return address


def encrypt_key(private_key_bytes, password):
    key = derive_key(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, private_key_bytes, None)


def decrypt_key(encrypted_data, password):
    key = derive_key(password)
    aesgcm = AESGCM(key)
    nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


def derive_key(password):
    return keccak(password.encode())[:16]


def read_key(key_store_file, password):
    with open(key_store_file, "r") as f:
        key_data = json.load(f)

    encrypted_private_key = base64.b64decode(key_data["private_key"])
    private_key_bytes = decrypt_key(encrypted_private_key, password)
    return SigningKey.from_string(private_key_bytes, curve=SECP256k1)


def get_address_from_keystore_file(key_store_file):
    with open(key_store_file, "r") as f:
        key_data = json.load(f)
    return key_data.get("address", "")


def key_and_address_from_hex_key(hex_key):
    hex_key = hex_key.lstrip("0x")
    try:
        private_key = SigningKey.from_string(binascii.unhexlify(hex_key), curve=SECP256k1)
        public_key = private_key.get_verifying_key().to_string()
        address = to_checksum_address(keccak(public_key)[-20:].hex())
        return private_key, address
    except binascii.Error:
        raise ValueError("Invalid hex key format")
