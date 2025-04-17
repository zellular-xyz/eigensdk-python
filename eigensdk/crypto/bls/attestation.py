import json
import os
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
        self.X = x
        self.Y = y
        _x = Fp()
        _x.setInt(x)
        self.X = _x
        _y = Fp()
        _y.setInt(y)
        self.Y = _y

    def add(self, a: "G1Point"):
        return self + a

    def sub(self, a: "G1Point"):
        return self - a

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
        self.Xa = xa
        self.Xb = xb
        self.Ya = ya
        self.Yb = yb

    def add(self, a: "G2Point"):
        return self + a

    def sub(self, a: "G2Point"):
        return self - a


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

    def from_json(_json: dict) -> "Signature":
        pass

    def add(self, a: "Signature"):
        return self + a

    def verify(self, pub_key: G2Point, msg_bytes: bytes) -> bool:
        return bn256Utils.verify_sig(self, pub_key, msg_bytes)


def new_zero_signature() -> Signature:
    return Signature(0, 0)


class PrivateKey(Fr):
    def __init__(self, secret: bytes = None):
        super().__init__()
        if not secret:
            self.setHashOf(os.urandom(64))
        else:
            int_key = int.from_bytes(secret, "big")
            self.setStr(f"{int_key}".encode("utf-8"), 10)

    def get_str(self) -> str:
        return self.getStr(16).decode("utf-8")  # .zfill(64)


def new_private_key(sk: bytes = b"") -> PrivateKey:
    return PrivateKey(sk)


class BLSKeyPair:
    def __init__(self, priv_key: PrivateKey = None) -> None:
        if not priv_key:
            self.priv_key = PrivateKey()
        else:
            self.priv_key = priv_key

        self.pub_g1 = bn256Utils.mul_by_generator_g1(self.priv_key).normalize()
        self.pub_g2 = bn256Utils.mul_by_generator_g2(self.priv_key).normalize()

    @staticmethod
    def from_string(sk: str, base=16) -> "BLSKeyPair":
        pk = PrivateKey()
        pk.setStr(sk.encode("utf-8"), base)
        return BLSKeyPair(pk)

    def save_to_file(self, _path: str, password: str):
        priv_key = "0x" + self.priv_key.getStr(16).decode("utf-8").rjust(64, "0")
        keystore_json = Account.encrypt(priv_key, password)
        keystore_json["pubKey"] = self.pub_g1.getStr().decode("utf-8")
        os.makedirs(os.path.dirname(_path), exist_ok=True)
        with open(_path, "w") as f:
            f.write(json.dumps(keystore_json))

    @staticmethod
    def read_from_file(_path: str, password: str):
        with open(_path, "r") as f:
            keystore_json = json.load(f)
        if "version" not in keystore_json:
            keystore_json["version"] = 3

        private_key = Account.decrypt(keystore_json, password)
        return BLSKeyPair(PrivateKey(bytes(private_key)))

    def sign_message(self, msg_bytes: bytes) -> Signature:
        h = bn256Utils.map_to_curve(msg_bytes)
        return self.sign_hashed_to_curve_message(h)

    def sign_hashed_to_curve_message(self, msg_map_point: G1Point) -> Signature:
        sig = (msg_map_point * self.priv_key).normalize()
        return Signature.from_g1_point(sig)

    def get_pub_g1(self) -> G1Point:
        return bn256Utils.mul_by_generator_g1(self.priv_key)

    def get_pub_g2(self) -> G2Point:
        return bn256Utils.mul_by_generator_g2(self.priv_key)


def new_key_pair(priv_key: PrivateKey) -> BLSKeyPair:
    return BLSKeyPair(priv_key)


def new_key_pair_from_string(sk: str) -> BLSKeyPair:
    return BLSKeyPair.from_string(sk)


def gen_random_bls_keys() -> BLSKeyPair:
    return BLSKeyPair()


def g1_to_tupple(g1):
    return (int(g1.getX().getStr()), int(g1.getY().getStr()))


def g2_to_tupple(g2):
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
