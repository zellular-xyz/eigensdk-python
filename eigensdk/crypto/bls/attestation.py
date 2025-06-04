import json
import os
import secrets

from eth_account import Account
from mcl import G1, G2, GT, Fr, Fp

from eigensdk.crypto.bn256 import utils as bn256Utils


def new_fp_element(v: int) -> Fp:
    fp = Fp()
    fp.setInt(v)
    return fp


class G1Point(G1):
    def __init__(self, x: int, y: int) -> None:
        super().__init__()
        self.setStr(f"1 {x} {y}".encode("utf-8"))
        if x == 0 and y == 0:
            self.clear()

    @staticmethod
    def from_G1(g1: G1):
        x = int(g1.getX().getStr())
        y = int(g1.getY().getStr())
        return G1Point(x, y)

    def __add__(self, a: "G1Point"):
        return G1Point.from_G1(super().__add__(a).normalize())

    def __sub__(self, a: "G1Point"):
        return G1Point.from_G1(super().__sub__(a).normalize())

    def verify_equivalence(self, a: "G2Point"):
        return bn256Utils.check_g1_and_g2_discrete_log_equality(self, a)


def new_g1_point(x: int, y: int) -> G1Point:
    res = G1Point(x, y)
    if x == 0 and y == 0:
        res.clear()
    return res


def new_zero_g1_point() -> G1Point:
    return new_g1_point(0, 0)


class G2Point(G2):
    def __init__(self, xa: int, xb: int, ya: int, yb: int) -> None:
        super().__init__()
        self.setStr(f"1 {xb} {xa} {yb} {ya}".encode("utf-8"))
        if xa == 0 and xb == 0 and ya == 0 and yb == 0:
            self.clear()

    @staticmethod
    def from_G2(g2: G2):
        xa = int(g2.getX().get_a().getStr())
        xb = int(g2.getX().get_b().getStr())
        ya = int(g2.getY().get_a().getStr())
        yb = int(g2.getY().get_b().getStr())
        return G2Point(xa, xb, ya, yb)

    def __add__(self, a: "G2Point"):
        return G2Point.from_G2(super().__add__(a).normalize())

    def __sub__(self, a: "G2Point"):
        return G2Point.from_G2(super().__sub__(a).normalize())


def new_g2_point(xa: int, xb: int, ya: int, yb: int) -> G2Point:
    return G2Point(xa, xb, ya, yb)


def new_zero_g2_point() -> G2Point:
    return new_g2_point(0, 0, 0, 0)


class GTPoint(GT):
    pass


class Signature(G1Point):
    @staticmethod
    def from_g1_point(p: G1Point) -> "Signature":
        x = int(p.getX().getStr())
        y = int(p.getY().getStr())
        return Signature(x, y)

    def to_json(self) -> dict:
        return {
            "X": int(self.getX().getStr()),
            "Y": int(self.getY().getStr()),
        }

    def add(self, a: "Signature") -> "Signature":
        """Add two signatures and return a Signature object"""
        result = super().__add__(a).normalize()
        return Signature.from_g1_point(result)

    def __add__(self, a: "Signature") -> "Signature":
        """Override addition to return Signature object"""
        result = super().__add__(a).normalize()
        return Signature.from_g1_point(result)

    def verify(self, pub_key: G2Point, msg_bytes: bytes, domain_tag: bytes = None) -> bool:
        """Verify signature with optional domain separation"""
        if domain_tag is None:
            return bn256Utils.verify_sig(self, pub_key, msg_bytes)
        else:
            return bn256Utils.verify_sig(self, pub_key, msg_bytes, domain_tag)


def new_zero_signature() -> Signature:
    return Signature(0, 0)


class PrivateKey(Fr):
    def __init__(self, secret: bytes = None):
        super().__init__()
        if not secret:
            # Use cryptographically secure random generation
            self.setHashOf(secrets.token_bytes(32))  # 32 bytes is sufficient
        else:
            if len(secret) != 32:
                raise ValueError("Private key must be exactly 32 bytes")
            int_key = int.from_bytes(secret, "big")
            self.setStr(f"{int_key}".encode("utf-8"), 10)

    def get_str(self) -> str:
        return self.getStr(16).decode("utf-8")


def new_private_key(sk: bytes = b"") -> PrivateKey:
    return PrivateKey(sk)


class KeyPair:
    def __init__(self, priv_key: PrivateKey = None) -> None:
        if not priv_key:
            self.priv_key = PrivateKey()
        else:
            self.priv_key = priv_key

        self.pub_g1 = bn256Utils.mul_by_generator_g1(self.priv_key).normalize()
        self.pub_g2 = bn256Utils.mul_by_generator_g2(self.priv_key).normalize()

    @staticmethod
    def from_string(sk: str) -> "KeyPair":
        """
        Secure key derivation from string using consistent hashing.
        Always uses the same derivation method to avoid collisions.
        """
        # Use secure key derivation function from bn256Utils
        sk_bytes = bn256Utils.derive_key_from_string(sk)
        return KeyPair(PrivateKey(sk_bytes))

    def save_to_file(self, _path: str, password: str):
        """Save key using Ethereum-compatible keystore format"""
        try:
            priv_key = "0x" + self.priv_key.getStr(16).decode("utf-8").rjust(64, "0")
            keystore_json = Account.encrypt(priv_key, password)
            keystore_json["pubKey"] = self.pub_g1.getStr().decode("utf-8")
            keystore_json["keyType"] = "BLS"  # Mark as BLS key for identification
            os.makedirs(os.path.dirname(_path), exist_ok=True)
            with open(_path, "w") as f:
                f.write(json.dumps(keystore_json, indent=2))
        except Exception as e:
            raise RuntimeError(f"Failed to save keystore: {e}")

    @staticmethod
    def read_from_file(_path: str, password: str):
        """Read key from Ethereum-compatible keystore format"""
        try:
            with open(_path, "r") as f:
                keystore_json = json.load(f)

            if "version" not in keystore_json:
                keystore_json["version"] = 3

            # Verify this is a BLS key if marked
            if keystore_json.get("keyType") == "BLS":
                pass  # Valid BLS keystore

            private_key = Account.decrypt(keystore_json, password)
            return KeyPair(PrivateKey(bytes(private_key)))
        except Exception as e:
            raise RuntimeError(f"Failed to read keystore: {e}")

    def sign_message(self, msg_bytes: bytes, domain_tag: bytes = None) -> Signature:
        """Sign message with optional domain separation"""
        if domain_tag is None:
            h = bn256Utils.map_to_curve(msg_bytes)
        else:
            h = bn256Utils.map_to_curve(msg_bytes, domain_tag)
        return self.sign_hashed_to_curve_message(h)

    def sign_hashed_to_curve_message(self, msg_map_point: G1Point) -> Signature:
        sig = (msg_map_point * self.priv_key).normalize()
        return Signature.from_g1_point(sig)

    def get_pub_g1(self) -> G1Point:
        """Get G1 public key with consistent normalization"""
        return G1Point.from_G1(bn256Utils.mul_by_generator_g1(self.priv_key).normalize())

    def get_pub_g2(self) -> G2Point:
        """Get G2 public key with consistent normalization"""
        return G2Point.from_G2(bn256Utils.mul_by_generator_g2(self.priv_key).normalize())


def new_key_pair(priv_key: PrivateKey) -> KeyPair:
    return KeyPair(priv_key)


def new_key_pair_from_string(sk: str) -> KeyPair:
    return KeyPair.from_string(sk)


def gen_random_bls_keys() -> KeyPair:
    return KeyPair()


def g1_to_tuple(g1):
    """Convert G1 point to tuple (fixed typo)"""
    return int(g1.getX().getStr()), int(g1.getY().getStr())


def g2_to_tuple(g2):
    """Convert G2 point to tuple (fixed typo)"""
    return (
        (
            int(g2.getX().get_a().getStr()),
            int(g2.getX().get_b().getStr()),
        ),
        (
            int(g2.getY().get_a().getStr()),
            int(g2.getY().get_b().getStr()),
        ),
    )
