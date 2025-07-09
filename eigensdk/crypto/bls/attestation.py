import json
import os
import secrets
from eth_account import Account
from mcl import G1, G2, GT, Fr, Fp
from eigensdk.crypto.bn256 import utils as bn256Utils


def new_fp_element(v: int) -> Fp:
    """Creates a new Fp element with the given integer value."""
    fp = Fp()
    fp.setInt(v)
    return fp


class G1Point(G1):
    """
    Represents a point on the G1 curve. Provides basic arithmetic operations.
    """
    def __init__(self, x: int, y: int) -> None:
        super().__init__()
        self.setStr(f"1 {x} {y}".encode("utf-8"))
        if x == 0 and y == 0:
            self.clear()

    def from_G1(g1: G1):
        """Creates a G1Point from an existing G1 object."""
        x = int(g1.getX().getStr())
        y = int(g1.getY().getStr())
        return G1Point(x, y)

    def __add__(self, a: "G1Point"):
        """
        Adds another G1Point to this point and returns the result.
        """
        return G1Point.from_G1(super().__add__(a).normalize())

    def __sub__(self, a: "G1Point"):
        """
        Subtracts another G1Point from this point and returns the result.
        """
        return G1Point.from_G1(super().__sub__(a).normalize())

    def verify_equivalence(self, a: "G2Point"):
        """
        Verifies if a G1Point and a G2Point represent the same underlying discrete logarithm. Useful for signature verification.
        """
        return bn256Utils.check_g1_and_g2_discrete_log_equality(self, a)


def new_g1_point(x: int, y: int) -> G1Point:
    """
    Constructs a new G1Point.
    """
    res = G1Point(x, y)
    if x == 0 and y == 0:
        res.clear()
    return res


def new_zero_g1_point() -> G1Point:
    """Creates a new G1Point representing the zero point."""
    return new_g1_point(0, 0)


class G2Point(G2):
    """
    Represents a point on the G2 curve.
    """
    def __init__(self, xa: int, xb: int, ya: int, yb: int) -> None:
        super().__init__()
        self.setStr(f"1 {xb} {xa} {yb} {ya}".encode("utf-8"))
        if xa == 0 and xb == 0 and ya == 0 and yb == 0:
            self.clear()

    def from_G2(g2: G2):
        """Creates a G2Point from an existing G2 object."""
        xa = int(g2.getX().get_a().getStr())
        xb = int(g2.getX().get_b().getStr())
        ya = int(g2.getY().get_a().getStr())
        yb = int(g2.getY().get_b().getStr())
        return G2Point(xa, xb, ya, yb)

    def __add__(self, a: "G2Point"):
        """Adds another G2Point to this point and returns the result."""
        return G2Point.from_G2(super().__add__(a).normalize())

    def __sub__(self, a: "G2Point"):
        """Subtracts another G2Point from this point and returns the result."""
        return G2Point.from_G2(super().__sub__(a).normalize())


def new_g2_point(xa: int, xb: int, ya: int, yb: int) -> G2Point:
    """
    Constructs a new G2Point.
    """
    return G2Point(xa, xb, ya, yb)


def new_zero_g2_point() -> G2Point:
    """Creates a new G2Point representing the zero point."""
    return new_g2_point(0, 0, 0, 0)


class GTPoint(GT):
    """Represents a point on the GT curve (target group of the pairing)."""
    pass


class Signature(G1Point):
    """
    A special type of G1Point specifically used for signatures.
    """
    @staticmethod
    def from_g1_point(p: G1Point) -> "Signature":
        """
        Constructs a Signature from a G1Point.
        """
        x = int(p.getX().getStr())
        y = int(p.getY().getStr())
        return Signature(x, y)

    def to_json(self) -> dict:
        """Converts the signature to a JSON-serializable dictionary."""
        return {
            "X": int(self.getX().getStr()),
            "Y": int(self.getY().getStr()),
        }

    def add(self, a: "Signature"):
        """Adds another signature to this signature."""
        return self + a

    def verify(self, pub_key: G2Point, msg_bytes: bytes) -> bool:
        """Verifies the signature against a public key and message."""
        return bn256Utils.verify_sig(self, pub_key, msg_bytes)


def new_zero_signature() -> Signature:
    """Creates a new signature representing the zero point."""
    return Signature(0, 0)


class PrivateKey(Fr):
    """
    Represents a BLS private key.
    """
    def __init__(self, secret: bytes = None):
        super().__init__()
        if not secret:
            self.setHashOf(secrets.token_bytes(32))
        else:
            int_key = int.from_bytes(secret, "big")
            self.setStr(f"{int_key}".encode("utf-8"), 10)

    def get_str(self) -> str:
        """
        Returns the private key as a hexadecimal string.
        """
        return self.getStr(16).decode("utf-8")  # .zfill(64)


def new_private_key(sk: bytes = b"") -> PrivateKey:
    """Creates a new BLS private key from the given secret bytes."""
    return PrivateKey(sk)


class KeyPair:
    """
    Represents a BLS key pair, including both private and public keys.
    """
    def __init__(self, priv_key: PrivateKey = None) -> None:
        if not priv_key:
            self.priv_key = PrivateKey()
        else:
            self.priv_key = priv_key

        self.pub_g1 = bn256Utils.mul_by_generator_g1(self.priv_key).normalize()
        self.pub_g2 = bn256Utils.mul_by_generator_g2(self.priv_key).normalize()

    @staticmethod
    def from_string(sk: str, base=16) -> "KeyPair":
        """
        Constructs a KeyPair from a private key string.
        """
        pk = PrivateKey()
        pk.setStr(sk.encode("utf-8"), base)
        return KeyPair(pk)

    def save_to_file(self, _path: str, password: str):
        """Saves the key pair to a keystore file encrypted with the given password."""
        priv_key = "0x" + self.priv_key.getStr(16).decode("utf-8").rjust(64, "0")
        keystore_json = Account.encrypt(priv_key, password)
        keystore_json["pubKey"] = self.pub_g1.getStr().decode("utf-8")
        os.makedirs(os.path.dirname(_path), exist_ok=True)
        with open(_path, "w") as f:
            f.write(json.dumps(keystore_json))

    @staticmethod
    def read_from_file(_path: str, password: str):
        """Loads a key pair from a keystore file using the given password."""
        with open(_path, "r") as f:
            keystore_json = json.load(f)
        if "version" not in keystore_json:
            keystore_json["version"] = 3

        private_key = Account.decrypt(keystore_json, password)
        return KeyPair(PrivateKey(bytes(private_key)))

    def sign_message(self, msg_bytes: bytes) -> Signature:
        """
        Signs a message using the private key of the key pair.
        """
        h = bn256Utils.map_to_curve(msg_bytes)
        return self.sign_hashed_to_curve_message(h)

    def sign_hashed_to_curve_message(self, msg_map_point: G1Point) -> Signature:
        """Signs a message that has already been hashed to the curve."""
        sig = (msg_map_point * self.priv_key).normalize()
        return Signature.from_g1_point(sig)

    def get_pub_g1(self) -> G1Point:
        """Returns the public key as a G1 point."""
        return bn256Utils.mul_by_generator_g1(self.priv_key)

    def get_pub_g2(self) -> G2Point:
        """Returns the public key as a G2 point."""
        return bn256Utils.mul_by_generator_g2(self.priv_key)


def new_key_pair(priv_key: PrivateKey) -> KeyPair:
    """Creates a new key pair from the given private key."""
    return KeyPair(priv_key)


def new_key_pair_from_string(sk: str) -> KeyPair:
    """Creates a new key pair from a private key string."""
    return KeyPair.from_string(sk)


def gen_random_bls_keys() -> KeyPair:
    """Generates a new random BLS key pair."""
    return KeyPair()


def g1_to_tupple(g1):
    """Converts a G1 point to a tuple of (x, y) coordinates."""
    return (int(g1.getX().getStr()), int(g1.getY().getStr()))


def g2_to_tupple(g2):
    """Converts a G2 point to a tuple of ((xa, xb), (ya, yb)) coordinates."""
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
