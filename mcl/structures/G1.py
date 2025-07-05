import types
import ctypes

from .. import utils
from .. import consts
from .. import builder
from .Fp import Fp
from .Fr import Fr


class G1(ctypes.Structure):
    _fields_ = [
        ("x", Fp),
        ("y", Fp),
        ("z", Fp),
    ]


G1.__add__ = builder.buildThreeOp(G1, "add")
G1.__eq__ = builder.buildIsEqual(G1)
G1.__mul__ = builder.buildMul(G1, Fr)
G1.__neg__ = builder.buildTwoOp(G1, "neg")
G1.__sub__ = builder.buildThreeOp(G1, "sub")
G1.normalize = builder.buildNormalize(G1)
G1.deserialize = builder.buildDeserialize(G1)
G1.getStr = builder.buildGetStr(G1)
G1.hashAndMapTo = builder.buildHashAndMapTo(G1)
G1.isZero = builder.buildIsZero(G1)
G1.serialize = builder.buildSerialize(G1)
G1.setStr = builder.buildSetStr(G1)
G1.getX = builder.buildGetSubArray(G1, 0, Fp)
G1.getY = builder.buildGetSubArray(G1, 1, Fp)
G1.getZ = builder.buildGetSubArray(G1, 2, Fp)
G1.clear = builder.buildClear(G1)
